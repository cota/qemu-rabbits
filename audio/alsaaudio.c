/*
 * QEMU ALSA audio driver
 *
 * Copyright (c) 2005 Vassili Karpov (malc)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
#include <alsa/asoundlib.h>
#include "vl.h"

#define AUDIO_CAP "alsa"
#include "audio_int.h"

typedef struct ALSAVoiceOut {
    HWVoiceOut hw;
    void *pcm_buf;
    snd_pcm_t *handle;
    int can_pause;
    int was_enabled;
} ALSAVoiceOut;

typedef struct ALSAVoiceIn {
    HWVoiceIn hw;
    snd_pcm_t *handle;
    void *pcm_buf;
    int can_pause;
} ALSAVoiceIn;

static struct {
    int size_in_usec_in;
    int size_in_usec_out;
    const char *pcm_name_in;
    const char *pcm_name_out;
    unsigned int buffer_size_in;
    unsigned int period_size_in;
    unsigned int buffer_size_out;
    unsigned int period_size_out;
    unsigned int threshold;

    int buffer_size_in_overriden;
    int period_size_in_overriden;

    int buffer_size_out_overriden;
    int period_size_out_overriden;
} conf = {
#ifdef HIGH_LATENCY
    .size_in_usec_in = 1,
    .size_in_usec_out = 1,
#endif
    .pcm_name_out = "hw:0,0",
    .pcm_name_in = "hw:0,0",
#ifdef HIGH_LATENCY
    .buffer_size_in = 400000,
    .period_size_in = 400000 / 4,
    .buffer_size_out = 400000,
    .period_size_out = 400000 / 4,
#else
#define DEFAULT_BUFFER_SIZE 1024
#define DEFAULT_PERIOD_SIZE 256
    .buffer_size_in = DEFAULT_BUFFER_SIZE,
    .period_size_in = DEFAULT_PERIOD_SIZE,
    .buffer_size_out = DEFAULT_BUFFER_SIZE,
    .period_size_out = DEFAULT_PERIOD_SIZE,
    .buffer_size_in_overriden = 0,
    .buffer_size_out_overriden = 0,
    .period_size_in_overriden = 0,
    .period_size_out_overriden = 0,
#endif
    .threshold = 0
};

struct alsa_params_req {
    int freq;
    audfmt_e fmt;
    int nchannels;
    unsigned int buffer_size;
    unsigned int period_size;
};

struct alsa_params_obt {
    int freq;
    audfmt_e fmt;
    int nchannels;
    int can_pause;
    snd_pcm_uframes_t buffer_size;
};

static void GCC_FMT_ATTR (2, 3) alsa_logerr (int err, const char *fmt, ...)
{
    va_list ap;

    va_start (ap, fmt);
    AUD_vlog (AUDIO_CAP, fmt, ap);
    va_end (ap);

    AUD_log (AUDIO_CAP, "Reason: %s\n", snd_strerror (err));
}

static void GCC_FMT_ATTR (3, 4) alsa_logerr2 (
    int err,
    const char *typ,
    const char *fmt,
    ...
    )
{
    va_list ap;

    AUD_log (AUDIO_CAP, "Can not initialize %s\n", typ);

    va_start (ap, fmt);
    AUD_vlog (AUDIO_CAP, fmt, ap);
    va_end (ap);

    AUD_log (AUDIO_CAP, "Reason: %s\n", snd_strerror (err));
}

static void alsa_anal_close (snd_pcm_t **handlep)
{
    int err = snd_pcm_close (*handlep);
    if (err) {
        alsa_logerr (err, "Failed to close PCM handle %p\n", *handlep);
    }
    *handlep = NULL;
}

static int alsa_write (SWVoiceOut *sw, void *buf, int len)
{
    return audio_pcm_sw_write (sw, buf, len);
}

static int aud_to_alsafmt (audfmt_e fmt)
{
    switch (fmt) {
    case AUD_FMT_S8:
        return SND_PCM_FORMAT_S8;

    case AUD_FMT_U8:
        return SND_PCM_FORMAT_U8;

    case AUD_FMT_S16:
        return SND_PCM_FORMAT_S16_LE;

    case AUD_FMT_U16:
        return SND_PCM_FORMAT_U16_LE;

    default:
        dolog ("Internal logic error: Bad audio format %d\n", fmt);
#ifdef DEBUG_AUDIO
        abort ();
#endif
        return SND_PCM_FORMAT_U8;
    }
}

static int alsa_to_audfmt (int alsafmt, audfmt_e *fmt, int *endianness)
{
    switch (alsafmt) {
    case SND_PCM_FORMAT_S8:
        *endianness = 0;
        *fmt = AUD_FMT_S8;
        break;

    case SND_PCM_FORMAT_U8:
        *endianness = 0;
        *fmt = AUD_FMT_U8;
        break;

    case SND_PCM_FORMAT_S16_LE:
        *endianness = 0;
        *fmt = AUD_FMT_S16;
        break;

    case SND_PCM_FORMAT_U16_LE:
        *endianness = 0;
        *fmt = AUD_FMT_U16;
        break;

    case SND_PCM_FORMAT_S16_BE:
        *endianness = 1;
        *fmt = AUD_FMT_S16;
        break;

    case SND_PCM_FORMAT_U16_BE:
        *endianness = 1;
        *fmt = AUD_FMT_U16;
        break;

    default:
        dolog ("Unrecognized audio format %d\n", alsafmt);
        return -1;
    }

    return 0;
}

#ifdef DEBUG_MISMATCHES
static void alsa_dump_info (struct alsa_params_req *req,
                            struct alsa_params_obt *obt)
{
    dolog ("parameter | requested value | obtained value\n");
    dolog ("format    |      %10d |     %10d\n", req->fmt, obt->fmt);
    dolog ("channels  |      %10d |     %10d\n",
           req->nchannels, obt->nchannels);
    dolog ("frequency |      %10d |     %10d\n", req->freq, obt->freq);
    dolog ("============================================\n");
    dolog ("requested: buffer size %d period size %d\n",
           req->buffer_size, req->period_size);
    dolog ("obtained: buffer size %ld\n", obt->buffer_size);
}
#endif

static void alsa_set_threshold (snd_pcm_t *handle, snd_pcm_uframes_t threshold)
{
    int err;
    snd_pcm_sw_params_t *sw_params;

    snd_pcm_sw_params_alloca (&sw_params);

    err = snd_pcm_sw_params_current (handle, sw_params);
    if (err < 0) {
        dolog ("Can not fully initialize DAC\n");
        alsa_logerr (err, "Failed to get current software parameters\n");
        return;
    }

    err = snd_pcm_sw_params_set_start_threshold (handle, sw_params, threshold);
    if (err < 0) {
        dolog ("Can not fully initialize DAC\n");
        alsa_logerr (err, "Failed to set software threshold to %ld\n",
                     threshold);
        return;
    }

    err = snd_pcm_sw_params (handle, sw_params);
    if (err < 0) {
        dolog ("Can not fully initialize DAC\n");
        alsa_logerr (err, "Failed to set software parameters\n");
        return;
    }
}

static int alsa_open (int in, struct alsa_params_req *req,
                      struct alsa_params_obt *obt, snd_pcm_t **handlep)
{
    snd_pcm_t *handle;
    snd_pcm_hw_params_t *hw_params;
    int err, freq, nchannels;
    const char *pcm_name = in ? conf.pcm_name_in : conf.pcm_name_out;
    unsigned int period_size, buffer_size;
    snd_pcm_uframes_t obt_buffer_size;
    const char *typ = in ? "ADC" : "DAC";

    freq = req->freq;
    period_size = req->period_size;
    buffer_size = req->buffer_size;
    nchannels = req->nchannels;

    snd_pcm_hw_params_alloca (&hw_params);

    err = snd_pcm_open (
        &handle,
        pcm_name,
        in ? SND_PCM_STREAM_CAPTURE : SND_PCM_STREAM_PLAYBACK,
        SND_PCM_NONBLOCK
        );
    if (err < 0) {
        alsa_logerr2 (err, typ, "Failed to open `%s':\n", pcm_name);
        return -1;
    }

    err = snd_pcm_hw_params_any (handle, hw_params);
    if (err < 0) {
        alsa_logerr2 (err, typ, "Failed to initialize hardware parameters\n");
        goto err;
    }

    err = snd_pcm_hw_params_set_access (
        handle,
        hw_params,
        SND_PCM_ACCESS_RW_INTERLEAVED
        );
    if (err < 0) {
        alsa_logerr2 (err, typ, "Failed to set access type\n");
        goto err;
    }

    err = snd_pcm_hw_params_set_format (handle, hw_params, req->fmt);
    if (err < 0) {
        alsa_logerr2 (err, typ, "Failed to set format %d\n", req->fmt);
        goto err;
    }

    err = snd_pcm_hw_params_set_rate_near (handle, hw_params, &freq, 0);
    if (err < 0) {
        alsa_logerr2 (err, typ, "Failed to set frequency %d\n", req->freq);
        goto err;
    }

    err = snd_pcm_hw_params_set_channels_near (
        handle,
        hw_params,
        &nchannels
        );
    if (err < 0) {
        alsa_logerr2 (err, typ, "Failed to set number of channels %d\n",
                      req->nchannels);
        goto err;
    }

    if (nchannels != 1 && nchannels != 2) {
        alsa_logerr2 (err, typ,
                      "Can not handle obtained number of channels %d\n",
                      nchannels);
        goto err;
    }

    if (!((in && conf.size_in_usec_in) || (!in && conf.size_in_usec_out))) {
        if (!buffer_size) {
            buffer_size = DEFAULT_BUFFER_SIZE;
            period_size= DEFAULT_PERIOD_SIZE;
        }
    }

    if (buffer_size) {
        if ((in && conf.size_in_usec_in) || (!in && conf.size_in_usec_out)) {
            if (period_size) {
                err = snd_pcm_hw_params_set_period_time_near (
                    handle,
                    hw_params,
                    &period_size,
                    0);
                if (err < 0) {
                    alsa_logerr2 (err, typ,
                                  "Failed to set period time %d\n",
                                  req->period_size);
                    goto err;
                }
            }

            err = snd_pcm_hw_params_set_buffer_time_near (
                handle,
                hw_params,
                &buffer_size,
                0);

            if (err < 0) {
                alsa_logerr2 (err, typ,
                              "Failed to set buffer time %d\n",
                              req->buffer_size);
                goto err;
            }
        }
        else {
            int dir;
            snd_pcm_uframes_t minval;

            if (period_size) {
                minval = period_size;
                dir = 0;

                err = snd_pcm_hw_params_get_period_size_min (
                    hw_params,
                    &minval,
                    &dir
                    );
                if (err < 0) {
                    alsa_logerr (
                        err,
                        "Can not get minmal period size for %s\n",
                        typ
                        );
                }
                else {
                    if (period_size < minval) {
                        if ((in && conf.period_size_in_overriden)
                            || (!in && conf.period_size_out_overriden)) {
                            dolog ("%s period size(%d) is less "
                                   "than minmal period size(%ld)\n",
                                   typ,
                                   period_size,
                                   minval);
                        }
                        period_size = minval;
                    }
                }

                err = snd_pcm_hw_params_set_period_size (
                    handle,
                    hw_params,
                    period_size,
                    0
                    );
                if (err < 0) {
                    alsa_logerr2 (err, typ, "Failed to set period size %d\n",
                                  req->period_size);
                    goto err;
                }
            }

            minval = buffer_size;
            err = snd_pcm_hw_params_get_buffer_size_min (
                hw_params,
                &minval
                );
            if (err < 0) {
                alsa_logerr (err, "Can not get minmal buffer size for %s\n",
                             typ);
            }
            else {
                if (buffer_size < minval) {
                    if ((in && conf.buffer_size_in_overriden)
                        || (!in && conf.buffer_size_out_overriden)) {
                        dolog (
                            "%s buffer size(%d) is less "
                            "than minimal buffer size(%ld)\n",
                            typ,
                            buffer_size,
                            minval
                            );
                    }
                    buffer_size = minval;
                }
            }

            err = snd_pcm_hw_params_set_buffer_size (
                handle,
                hw_params,
                buffer_size
                );
            if (err < 0) {
                alsa_logerr2 (err, typ, "Failed to set buffer size %d\n",
                              req->buffer_size);
                goto err;
            }
        }
    }
    else {
        dolog ("warning: buffer size is not set\n");
    }

    err = snd_pcm_hw_params (handle, hw_params);
    if (err < 0) {
        alsa_logerr2 (err, typ, "Failed to apply audio parameters\n");
        goto err;
    }

    err = snd_pcm_hw_params_get_buffer_size (hw_params, &obt_buffer_size);
    if (err < 0) {
        alsa_logerr2 (err, typ, "Failed to get buffer size\n");
        goto err;
    }

    err = snd_pcm_prepare (handle);
    if (err < 0) {
        alsa_logerr2 (err, typ, "Can not prepare handle %p\n", handle);
        goto err;
    }

    obt->can_pause = snd_pcm_hw_params_can_pause (hw_params);
    if (obt->can_pause < 0) {
        alsa_logerr (err, "Can not get pause capability for %s\n", typ);
        obt->can_pause = 0;
    }

    if (!in && conf.threshold) {
        snd_pcm_uframes_t threshold;
        int bytes_per_sec;

        bytes_per_sec = freq
            << (nchannels == 2)
            << (req->fmt == AUD_FMT_S16 || req->fmt == AUD_FMT_U16);

        threshold = (conf.threshold * bytes_per_sec) / 1000;
        alsa_set_threshold (handle, threshold);
    }

    obt->fmt = req->fmt;
    obt->nchannels = nchannels;
    obt->freq = freq;
    obt->buffer_size = snd_pcm_frames_to_bytes (handle, obt_buffer_size);
    *handlep = handle;

    if (obt->fmt != req->fmt ||
        obt->nchannels != req->nchannels ||
        obt->freq != req->freq) {
#ifdef DEBUG_MISMATCHES
        dolog ("Audio paramters mismatch for %s\n", typ);
        alsa_dump_info (req, obt);
#endif
    }

#ifdef DEBUG
    alsa_dump_info (req, obt);
#endif
    return 0;

 err:
    alsa_anal_close (&handle);
    return -1;
}

static int alsa_recover (snd_pcm_t *handle)
{
    int err = snd_pcm_prepare (handle);
    if (err < 0) {
        alsa_logerr (err, "Failed to prepare handle %p\n", handle);
        return -1;
    }
    return 0;
}

static int alsa_run_out (HWVoiceOut *hw)
{
    ALSAVoiceOut *alsa = (ALSAVoiceOut *) hw;
    int rpos, live, decr;
    int samples;
    uint8_t *dst;
    st_sample_t *src;
    snd_pcm_sframes_t avail;

    live = audio_pcm_hw_get_live_out (hw);
    if (!live) {
        return 0;
    }

    avail = snd_pcm_avail_update (alsa->handle);
    if (avail < 0) {
        if (avail == -EPIPE) {
            if (!alsa_recover (alsa->handle)) {
                avail = snd_pcm_avail_update (alsa->handle);
                if (avail >= 0) {
                    goto ok;
                }
            }
        }

        alsa_logerr (avail, "Can not get amount free space\n");
        return 0;
    }

 ok:
    decr = audio_MIN (live, avail);
    samples = decr;
    rpos = hw->rpos;
    while (samples) {
        int left_till_end_samples = hw->samples - rpos;
        int convert_samples = audio_MIN (samples, left_till_end_samples);
        snd_pcm_sframes_t written;

        src = hw->mix_buf + rpos;
        dst = advance (alsa->pcm_buf, rpos << hw->info.shift);

        hw->clip (dst, src, convert_samples);

    again:
        written = snd_pcm_writei (alsa->handle, dst, convert_samples);

        if (written < 0) {
            switch (written) {
            case -EPIPE:
                if (!alsa_recover (alsa->handle)) {
                    goto again;
                }
                dolog (
                    "Failed to write %d frames to %p, handle %p not prepared\n",
                    convert_samples,
                    dst,
                    alsa->handle
                    );
                goto exit;

            case -EAGAIN:
                goto again;

            default:
                alsa_logerr (written, "Failed to write %d frames to %p\n",
                             convert_samples, dst);
                goto exit;
            }
        }

        mixeng_clear (src, written);
        rpos = (rpos + written) % hw->samples;
        samples -= written;
    }

 exit:
    hw->rpos = rpos;
    return decr;
}

static void alsa_fini_out (HWVoiceOut *hw)
{
    ALSAVoiceOut *alsa = (ALSAVoiceOut *) hw;

    ldebug ("alsa_fini\n");
    alsa_anal_close (&alsa->handle);

    if (alsa->pcm_buf) {
        qemu_free (alsa->pcm_buf);
        alsa->pcm_buf = NULL;
    }
}

static int alsa_init_out (HWVoiceOut *hw, int freq, int nchannels, audfmt_e fmt)
{
    ALSAVoiceOut *alsa = (ALSAVoiceOut *) hw;
    struct alsa_params_req req;
    struct alsa_params_obt obt;
    audfmt_e effective_fmt;
    int endianness;
    int err;
    snd_pcm_t *handle;

    req.fmt = aud_to_alsafmt (fmt);
    req.freq = freq;
    req.nchannels = nchannels;
    req.period_size = conf.period_size_out;
    req.buffer_size = conf.buffer_size_out;

    if (alsa_open (0, &req, &obt, &handle)) {
        return -1;
    }

    err = alsa_to_audfmt (obt.fmt, &effective_fmt, &endianness);
    if (err) {
        alsa_anal_close (&handle);
        return -1;
    }

    audio_pcm_init_info (
        &hw->info,
        obt.freq,
        obt.nchannels,
        effective_fmt,
        audio_need_to_swap_endian (endianness)
        );
    alsa->can_pause = obt.can_pause;
    hw->bufsize = obt.buffer_size;

    alsa->pcm_buf = qemu_mallocz (hw->bufsize);
    if (!alsa->pcm_buf) {
        alsa_anal_close (&handle);
        return -1;
    }

    alsa->handle = handle;
    alsa->was_enabled = 0;
    return 0;
}

static int alsa_ctl_out (HWVoiceOut *hw, int cmd, ...)
{
    int err;
    ALSAVoiceOut *alsa = (ALSAVoiceOut *) hw;

    switch (cmd) {
    case VOICE_ENABLE:
        ldebug ("enabling voice\n");
        audio_pcm_info_clear_buf (&hw->info, alsa->pcm_buf, hw->samples);
        if (alsa->can_pause) {
            /* Why this was_enabled madness is needed at all?? */
            if (alsa->was_enabled) {
                err = snd_pcm_pause (alsa->handle, 0);
                if (err < 0) {
                    alsa_logerr (err, "Failed to resume playing\n");
                    /* not fatal really */
                }
            }
            else {
                alsa->was_enabled = 1;
            }
        }
        break;

    case VOICE_DISABLE:
        ldebug ("disabling voice\n");
        if (alsa->can_pause) {
            err = snd_pcm_pause (alsa->handle, 1);
            if (err < 0) {
                alsa_logerr (err, "Failed to stop playing\n");
                /* not fatal really */
            }
        }
        break;
    }
    return 0;
}

static int alsa_init_in (HWVoiceIn *hw,
                        int freq, int nchannels, audfmt_e fmt)
{
    ALSAVoiceIn *alsa = (ALSAVoiceIn *) hw;
    struct alsa_params_req req;
    struct alsa_params_obt obt;
    int endianness;
    int err;
    audfmt_e effective_fmt;
    snd_pcm_t *handle;

    req.fmt = aud_to_alsafmt (fmt);
    req.freq = freq;
    req.nchannels = nchannels;
    req.period_size = conf.period_size_in;
    req.buffer_size = conf.buffer_size_in;

    if (alsa_open (1, &req, &obt, &handle)) {
        return -1;
    }

    err = alsa_to_audfmt (obt.fmt, &effective_fmt, &endianness);
    if (err) {
        alsa_anal_close (&handle);
        return -1;
    }

    audio_pcm_init_info (
        &hw->info,
        obt.freq,
        obt.nchannels,
        effective_fmt,
        audio_need_to_swap_endian (endianness)
        );
    alsa->can_pause = obt.can_pause;
    hw->bufsize = obt.buffer_size;
    alsa->pcm_buf = qemu_mallocz (hw->bufsize);
    if (!alsa->pcm_buf) {
        alsa_anal_close (&handle);
        return -1;
    }

    alsa->handle = handle;
    return 0;
}

static void alsa_fini_in (HWVoiceIn *hw)
{
    ALSAVoiceIn *alsa = (ALSAVoiceIn *) hw;

    alsa_anal_close (&alsa->handle);

    if (alsa->pcm_buf) {
        qemu_free (alsa->pcm_buf);
        alsa->pcm_buf = NULL;
    }
}

static int alsa_run_in (HWVoiceIn *hw)
{
    ALSAVoiceIn *alsa = (ALSAVoiceIn *) hw;
    int hwshift = hw->info.shift;
    int i;
    int live = audio_pcm_hw_get_live_in (hw);
    int dead = hw->samples - live;
    struct {
        int add;
        int len;
    } bufs[2] = {
        { hw->wpos, 0 },
        { 0, 0 }
    };

    snd_pcm_uframes_t read_samples = 0;

    if (!dead) {
        return 0;
    }

    if (hw->wpos + dead > hw->samples) {
        bufs[0].len = (hw->samples - hw->wpos);
        bufs[1].len = (dead - (hw->samples - hw->wpos));
    }
    else {
        bufs[0].len = dead;
    }


    for (i = 0; i < 2; ++i) {
        void *src;
        st_sample_t *dst;
        snd_pcm_sframes_t nread;
        snd_pcm_uframes_t len;

        len = bufs[i].len;

        src = advance (alsa->pcm_buf, bufs[i].add << hwshift);
        dst = hw->conv_buf + bufs[i].add;

        while (len) {
            nread = snd_pcm_readi (alsa->handle, src, len);

            if (nread < 0) {
                switch (nread) {
                case -EPIPE:
                    if (!alsa_recover (alsa->handle)) {
                        continue;
                    }
                    dolog (
                        "Failed to read %ld frames from %p, "
                        "handle %p not prepared\n",
                        len,
                        src,
                        alsa->handle
                        );
                    goto exit;

                case -EAGAIN:
                    continue;

                default:
                    alsa_logerr (
                        nread,
                        "Failed to read %ld frames from %p\n",
                        len,
                        src
                        );
                    goto exit;
                }
            }

            hw->conv (dst, src, nread, &nominal_volume);

            src = advance (src, nread << hwshift);
            dst += nread;

            read_samples += nread;
            len -= nread;
        }
    }

 exit:
    hw->wpos = (hw->wpos + read_samples) % hw->samples;
    return read_samples;
}

static int alsa_read (SWVoiceIn *sw, void *buf, int size)
{
    return audio_pcm_sw_read (sw, buf, size);
}

static int alsa_ctl_in (HWVoiceIn *hw, int cmd, ...)
{
    (void) hw;
    (void) cmd;
    return 0;
}

static void *alsa_audio_init (void)
{
    return &conf;
}

static void alsa_audio_fini (void *opaque)
{
    (void) opaque;
}

static struct audio_option alsa_options[] = {
    {"DAC_SIZE_IN_USEC", AUD_OPT_BOOL, &conf.size_in_usec_out,
     "DAC period/buffer size in microseconds (otherwise in frames)", NULL, 0},
    {"DAC_PERIOD_SIZE", AUD_OPT_INT, &conf.period_size_out,
     "DAC period size", &conf.period_size_out_overriden, 0},
    {"DAC_BUFFER_SIZE", AUD_OPT_INT, &conf.buffer_size_out,
     "DAC buffer size", &conf.buffer_size_out_overriden, 0},

    {"ADC_SIZE_IN_USEC", AUD_OPT_BOOL, &conf.size_in_usec_in,
     "ADC period/buffer size in microseconds (otherwise in frames)", NULL, 0},
    {"ADC_PERIOD_SIZE", AUD_OPT_INT, &conf.period_size_in,
     "ADC period size", &conf.period_size_in_overriden, 0},
    {"ADC_BUFFER_SIZE", AUD_OPT_INT, &conf.buffer_size_in,
     "ADC buffer size", &conf.buffer_size_in_overriden, 0},

    {"THRESHOLD", AUD_OPT_INT, &conf.threshold,
     "(undocumented)", NULL, 0},

    {"DAC_DEV", AUD_OPT_STR, &conf.pcm_name_out,
     "DAC device name (for instance dmix)", NULL, 0},

    {"ADC_DEV", AUD_OPT_STR, &conf.pcm_name_in,
     "ADC device name", NULL, 0},
    {NULL, 0, NULL, NULL, NULL, 0}
};

static struct audio_pcm_ops alsa_pcm_ops = {
    alsa_init_out,
    alsa_fini_out,
    alsa_run_out,
    alsa_write,
    alsa_ctl_out,

    alsa_init_in,
    alsa_fini_in,
    alsa_run_in,
    alsa_read,
    alsa_ctl_in
};

struct audio_driver alsa_audio_driver = {
    INIT_FIELD (name           = ) "alsa",
    INIT_FIELD (descr          = ) "ALSA http://www.alsa-project.org",
    INIT_FIELD (options        = ) alsa_options,
    INIT_FIELD (init           = ) alsa_audio_init,
    INIT_FIELD (fini           = ) alsa_audio_fini,
    INIT_FIELD (pcm_ops        = ) &alsa_pcm_ops,
    INIT_FIELD (can_be_default = ) 1,
    INIT_FIELD (max_voices_out = ) INT_MAX,
    INIT_FIELD (max_voices_in  = ) INT_MAX,
    INIT_FIELD (voice_size_out = ) sizeof (ALSAVoiceOut),
    INIT_FIELD (voice_size_in  = ) sizeof (ALSAVoiceIn)
};