/*
 * IDirect3DSurface9 implementation
 *
 * Copyright 2002-2005 Jason Edmeades
 *                     Raphael Junqueira
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include "d3d9_private.h"

WINE_DEFAULT_DEBUG_CHANNEL(d3d9);

static inline struct d3d9_surface *impl_from_IDirect3DSurface9(IDirect3DSurface9 *iface)
{
    return CONTAINING_RECORD(iface, struct d3d9_surface, IDirect3DSurface9_iface);
}

static HRESULT WINAPI d3d9_surface_QueryInterface(IDirect3DSurface9 *iface, REFIID riid, void **out)
{
    TRACE("iface %p, riid %s, out %p.\n", iface, debugstr_guid(riid), out);

    if (IsEqualGUID(riid, &IID_IDirect3DSurface9)
            || IsEqualGUID(riid, &IID_IDirect3DResource9)
            || IsEqualGUID(riid, &IID_IUnknown))
    {
        IDirect3DSurface9_AddRef(iface);
        *out = iface;
        return S_OK;
    }

    WARN("%s not implemented, returning E_NOINTERFACE.\n", debugstr_guid(riid));

    *out = NULL;
    return E_NOINTERFACE;
}

static ULONG WINAPI d3d9_surface_AddRef(IDirect3DSurface9 *iface)
{
    struct d3d9_surface *surface = impl_from_IDirect3DSurface9(iface);
    ULONG refcount;

    TRACE("iface %p.\n", iface);

    if (surface->texture)
    {
        TRACE("Forwarding to %p.\n", surface->texture);
        return IDirect3DBaseTexture9_AddRef(&surface->texture->IDirect3DBaseTexture9_iface);
    }

    refcount = InterlockedIncrement(&surface->resource.refcount);
    TRACE("%p increasing refcount to %lu.\n", iface, refcount);

    if (refcount == 1)
    {
        if (surface->parent_device)
            IDirect3DDevice9Ex_AddRef(surface->parent_device);
        if (surface->wined3d_rtv)
            wined3d_rendertarget_view_incref(surface->wined3d_rtv);
        wined3d_texture_incref(surface->wined3d_texture);
        if (surface->swapchain)
            wined3d_swapchain_incref(surface->swapchain);
    }

    return refcount;
}

static ULONG WINAPI d3d9_surface_Release(IDirect3DSurface9 *iface)
{
    struct d3d9_surface *surface = impl_from_IDirect3DSurface9(iface);
    ULONG refcount;

    TRACE("iface %p.\n", iface);

    if (surface->texture)
    {
        TRACE("Forwarding to %p.\n", surface->texture);
        return IDirect3DBaseTexture9_Release(&surface->texture->IDirect3DBaseTexture9_iface);
    }

    if (!surface->resource.refcount)
    {
        WARN("Surface does not have any references.\n");
        return 0;
    }

    refcount = InterlockedDecrement(&surface->resource.refcount);
    TRACE("%p decreasing refcount to %lu.\n", iface, refcount);

    if (!refcount)
    {
        IDirect3DDevice9Ex *parent_device = surface->parent_device;

        if (surface->wined3d_rtv)
            wined3d_rendertarget_view_decref(surface->wined3d_rtv);
        if (surface->swapchain)
            wined3d_swapchain_decref(surface->swapchain);
        /* Releasing the texture may free the d3d9 object, so do not access it
         * after releasing the texture. */
        wined3d_texture_decref(surface->wined3d_texture);

        /* Release the device last, as it may cause the device to be destroyed. */
        if (parent_device)
            IDirect3DDevice9Ex_Release(parent_device);
    }

    return refcount;
}

static HRESULT WINAPI d3d9_surface_GetDevice(IDirect3DSurface9 *iface, IDirect3DDevice9 **device)
{
    struct d3d9_surface *surface = impl_from_IDirect3DSurface9(iface);

    TRACE("iface %p, device %p.\n", iface, device);

    if (surface->texture)
        return IDirect3DBaseTexture9_GetDevice(&surface->texture->IDirect3DBaseTexture9_iface, device);

    *device = (IDirect3DDevice9 *)surface->parent_device;
    IDirect3DDevice9_AddRef(*device);

    TRACE("Returning device %p.\n", *device);

    return D3D_OK;
}

static HRESULT WINAPI d3d9_surface_SetPrivateData(IDirect3DSurface9 *iface, REFGUID guid,
        const void *data, DWORD data_size, DWORD flags)
{
    struct d3d9_surface *surface = impl_from_IDirect3DSurface9(iface);
    TRACE("iface %p, guid %s, data %p, data_size %lu, flags %#lx.\n",
            iface, debugstr_guid(guid), data, data_size, flags);

    return d3d9_resource_set_private_data(&surface->resource, guid, data, data_size, flags);
}

static HRESULT WINAPI d3d9_surface_GetPrivateData(IDirect3DSurface9 *iface, REFGUID guid,
        void *data, DWORD *data_size)
{
    struct d3d9_surface *surface = impl_from_IDirect3DSurface9(iface);
    TRACE("iface %p, guid %s, data %p, data_size %p.\n",
            iface, debugstr_guid(guid), data, data_size);

    return d3d9_resource_get_private_data(&surface->resource, guid, data, data_size);
}

static HRESULT WINAPI d3d9_surface_FreePrivateData(IDirect3DSurface9 *iface, REFGUID guid)
{
    struct d3d9_surface *surface = impl_from_IDirect3DSurface9(iface);
    TRACE("iface %p, guid %s.\n", iface, debugstr_guid(guid));

    return d3d9_resource_free_private_data(&surface->resource, guid);
}

static DWORD WINAPI d3d9_surface_SetPriority(IDirect3DSurface9 *iface, DWORD priority)
{
    TRACE("iface %p, priority %lu. Ignored on surfaces.\n", iface, priority);
    return 0;
}

static DWORD WINAPI d3d9_surface_GetPriority(IDirect3DSurface9 *iface)
{
    TRACE("iface %p. Ignored on surfaces.\n", iface);
    return 0;
}

static void WINAPI d3d9_surface_PreLoad(IDirect3DSurface9 *iface)
{
    struct d3d9_surface *surface = impl_from_IDirect3DSurface9(iface);

    TRACE("iface %p.\n", iface);

    wined3d_mutex_lock();
    wined3d_resource_preload(wined3d_texture_get_resource(surface->wined3d_texture));
    wined3d_mutex_unlock();
}

static D3DRESOURCETYPE WINAPI d3d9_surface_GetType(IDirect3DSurface9 *iface)
{
    TRACE("iface %p.\n", iface);

    return D3DRTYPE_SURFACE;
}

static HRESULT WINAPI d3d9_surface_GetContainer(IDirect3DSurface9 *iface, REFIID riid, void **container)
{
    struct d3d9_surface *surface = impl_from_IDirect3DSurface9(iface);
    HRESULT hr;

    TRACE("iface %p, riid %s, container %p.\n", iface, debugstr_guid(riid), container);

    if (!surface->container)
        return E_NOINTERFACE;

    hr = IUnknown_QueryInterface(surface->container, riid, container);

    TRACE("Returning %p.\n", *container);

    return hr;
}

static HRESULT WINAPI d3d9_surface_GetDesc(IDirect3DSurface9 *iface, D3DSURFACE_DESC *desc)
{
    struct d3d9_surface *surface = impl_from_IDirect3DSurface9(iface);
    struct wined3d_sub_resource_desc wined3d_desc;

    TRACE("iface %p, desc %p.\n", iface, desc);

    wined3d_mutex_lock();
    wined3d_texture_get_sub_resource_desc(surface->wined3d_texture, surface->sub_resource_idx, &wined3d_desc);
    wined3d_mutex_unlock();

    desc->Format = d3dformat_from_wined3dformat(wined3d_desc.format);
    desc->Type = D3DRTYPE_SURFACE;
    desc->Usage = d3dusage_from_wined3dusage(wined3d_desc.usage, wined3d_desc.bind_flags);
    desc->Pool = d3dpool_from_wined3daccess(wined3d_desc.access, wined3d_desc.usage);
    desc->MultiSampleType = d3dmultisample_type_from_wined3d(wined3d_desc.multisample_type);
    desc->MultiSampleQuality = wined3d_desc.multisample_quality;
    desc->Width = wined3d_desc.width;
    desc->Height = wined3d_desc.height;

    return D3D_OK;
}

/* ---------- Melammu per-slot thumbnail injection ----------
 *
 * CatSystem2 (CMVS64) calls StretchRect(backbuffer → 192×108 RT) then LockRect(0x800)
 * once for EACH visible save slot when the save/load screen renders.  By counting
 * StretchRect events we can determine which slot is being rendered and inject the
 * screenshot that was taken at that slot's save time.
 *
 * Communication files. melammu_snap.bgra has multiple writers: Melammu (macOS
 * launcher, SCK-based — see GameCaptureService.swift / LibraryViewModel), plus
 * three wine-side writers (device.c's blt-based capture and last-good-frame
 * paths, and swingby_write_last_good_snap_file below) that raced against the
 * launcher writer and produced black thumbnails; see research/state/thumbnail.md
 * for the resolved design (launcher SCK is now the sole real-pixel source).
 * The per-slot files below are launcher-written only:
 *   /tmp/melammu_snap.bgra          – fallback: most recent screenshot (persistent)
 *   /tmp/melammu_snap_NNN.bgra      – per-slot snap for slot NNN (written at save time)
 *   /tmp/melammu_page_base.txt      – first slot number of the current save-screen page
 *   /tmp/melammu_inject_dat_path.txt – Windows path to the .dat file just saved
 */

/* Shared with device.c: pauses auto-capture while save screen is open. */
extern UINT swingby_save_screen_cooldown;
extern DWORD melammu_snap_tick;
extern DWORD swingby_rt_snap_tick;
extern BOOL swingby_rt_capture_active;
extern BOOL swingby_observe_only;
extern BOOL swingby_capture_is_enabled(void);
extern void swingby_diag(const char *fmt, ...);

static void swingby_free_pix_cache(void); /* forward declaration */

/* Simple pixel cache shared across all inject calls for a given snap file. */
static struct {
    char         path[64];
    BYTE        *pixels;
    unsigned int fw, fh, fstride;
} s_pix_cache;

/* Registry: maps 192x108 surface ifaces → 0-indexed file slot numbers. */
#define SWINGBY_MAX_SLOTS 18
static struct { IDirect3DSurface9 *iface; unsigned int slot; } s_reg[SWINGBY_MAX_SLOTS];
static unsigned int s_reg_count     = 0;
static unsigned int s_reg_page_base = (unsigned int)-1; /* sentinel: unset */
static DWORD        s_reg_last_tick = 0;

static unsigned int swingby_registry_slot(IDirect3DSurface9 *iface)
{
    DWORD now = GetTickCount();
    unsigned int i, page_base;
    FILE *f;

    /* Flush if idle > 1 s (page changed or save screen reopened). */
    if (s_reg_count > 0 && (DWORD)(now - s_reg_last_tick) > 1000) {
        s_reg_count = 0;
        s_reg_page_base = (unsigned int)-1;
        swingby_free_pix_cache();
    }
    s_reg_last_tick = now;

    if (s_reg_page_base == (unsigned int)-1) {
        page_base = 0;
        f = fopen("Z:\\tmp\\melammu_page_base.txt", "rb");
        if (f) { fscanf(f, "%u", &page_base); fclose(f); }
        s_reg_page_base = page_base;
    }

    for (i = 0; i < s_reg_count; i++)
        if (s_reg[i].iface == iface) return s_reg[i].slot;

    if (s_reg_count < SWINGBY_MAX_SLOTS) {
        unsigned int slot = s_reg_page_base + s_reg_count;
        s_reg[s_reg_count].iface = iface;
        s_reg[s_reg_count].slot  = slot;
        s_reg_count++;
        return slot;
    }
    return (unsigned int)-1;
}

static void swingby_free_pix_cache(void)
{
    if (s_pix_cache.pixels) {
        HeapFree(GetProcessHeap(), 0, s_pix_cache.pixels);
        s_pix_cache.pixels = NULL;
        s_pix_cache.path[0] = '\0';
    }
}

/* Load pixels from a snap file.  Returns FALSE on failure.
 * Caches the last loaded file to avoid redundant reads for the same slot. */
static BOOL swingby_load_snap_file(const char *path,
    BYTE **out_px, unsigned int *out_fw, unsigned int *out_fh, unsigned int *out_fstride)
{
    unsigned int fw = 0, fh = 0, fstride = 0;
    SIZE_T pix_size;
    BYTE *px;
    FILE *f;

    /* Return cached pixels if path unchanged. */
    if (s_pix_cache.pixels && strcmp(s_pix_cache.path, path) == 0) {
        *out_px = s_pix_cache.pixels; *out_fw = s_pix_cache.fw;
        *out_fh = s_pix_cache.fh;    *out_fstride = s_pix_cache.fstride;
        return TRUE;
    }

    f = fopen(path, "rb");
    if (!f) return FALSE;
    if (fread(&fw, 4, 1, f) != 1 || fread(&fh, 4, 1, f) != 1 ||
        fread(&fstride, 4, 1, f) != 1 || fw <= 1 || fh <= 1 || fstride < fw * 4)
    { fclose(f); return FALSE; }
    pix_size = (SIZE_T)fstride * fh;
    px = HeapAlloc(GetProcessHeap(), 0, pix_size);
    if (!px || fread(px, 1, pix_size, f) != pix_size)
    { HeapFree(GetProcessHeap(), 0, px); fclose(f); return FALSE; }
    fclose(f);

    swingby_free_pix_cache();
    s_pix_cache.pixels  = px;
    s_pix_cache.fw      = fw;
    s_pix_cache.fh      = fh;
    s_pix_cache.fstride = fstride;
    { size_t n = strlen(path); if (n >= sizeof(s_pix_cache.path)) n = sizeof(s_pix_cache.path)-1;
      memcpy(s_pix_cache.path, path, n); s_pix_cache.path[n] = '\0'; }

    *out_px = px; *out_fw = fw; *out_fh = fh; *out_fstride = fstride;
    return TRUE;
}

/* Blit pixels (top-down) into the locked surface buffer (bottom-up readback). */
static void swingby_blit(void *dst_data, unsigned int dst_pitch,
    const BYTE *src_px, unsigned int src_fw, unsigned int src_fh, unsigned int src_fstride)
{
    unsigned int dy, dx;
    for (dy = 0; dy < 108; dy++)
    {
        unsigned int sy = (unsigned int)((UINT64)dy * src_fh / 108);
        const BYTE *src = src_px + (SIZE_T)sy * src_fstride;
        BYTE       *dst = (BYTE *)dst_data + (SIZE_T)dy * dst_pitch;
        for (dx = 0; dx < 192; dx++)
        {
            unsigned int sx = (unsigned int)((UINT64)dx * src_fw / 192);
            dst[dx*4+0] = src[sx*4+0];
            dst[dx*4+1] = src[sx*4+1];
            dst[dx*4+2] = src[sx*4+2];
            dst[dx*4+3] = 0xFF;
        }
    }
}

/* Surface pointer set by StretchRect; cleared after one-shot injection. */
static IDirect3DSurface9 *s_inject_pending_surf = NULL;
static DWORD               s_inject_pending_tick = 0;
static IDirect3DSurface9 *s_rtdata_dst_surf = NULL;
static IDirect3DSurface9 *s_rtdata_src_surf = NULL;
static DWORD               s_rtdata_tick = 0;
static unsigned int        s_rtdata_serial = 0;
static BOOL                s_rtdata_lock_logged = FALSE;

/* Called from device.c on every StretchRect to a 192x108 destination. */
void swingby_on_stretchrect(IDirect3DSurface9 *dest)
{
    s_inject_pending_surf = dest;
    s_inject_pending_tick = GetTickCount();
    swingby_free_pix_cache(); /* Fresh snap was just written; invalidate stale cache. */
    { FILE *lg = fopen("Z:\\tmp\\melammu_trace.txt","a");
      if (lg) { fprintf(lg,"stretchrect dest=%p\n",(void*)dest); fclose(lg); } }
}

/* Called from device.c after GetRenderTargetData has copied render_target -> dst. */
void swingby_on_get_render_target_data(IDirect3DSurface9 *src, IDirect3DSurface9 *dst)
{
    s_inject_pending_surf = dst;
    s_inject_pending_tick = GetTickCount();
    s_rtdata_src_surf = src;
    s_rtdata_dst_surf = dst;
    s_rtdata_tick = s_inject_pending_tick;
    s_rtdata_serial++;
    s_rtdata_lock_logged = FALSE;
    { FILE *lg = fopen("Z:\\tmp\\melammu_trace.txt","a");
      if (lg) { fprintf(lg,"getrtdata_set serial=%u src=%p dst=%p\n",
          s_rtdata_serial,(void*)src,(void*)dst); fclose(lg); } }
}

/* Inject the per-slot snap (melammu_snap_NNN.bgra) into the locked surface buffer.
 * Tries /tmp first (live session), then ~/Library/Application Support/Melammu/snaps/
 * for persistence across reboots.
 * Returns 1 if a snap was found and blitted, 0 otherwise. */
static int swingby_inject_snap_slot(void *data, unsigned int row_pitch, int slot)
{
    char         path[512];
    BYTE        *px = NULL;
    unsigned int fw, fh, fstride;

    /* 1. Try per-slot snap in /tmp (written by Swift periodic capture). */
    snprintf(path, sizeof(path), "Z:\\tmp\\melammu_snap_%03d.bgra", slot);
    if (swingby_load_snap_file(path, &px, &fw, &fh, &fstride))
    {
        swingby_blit(data, row_pitch, px, fw, fh, fstride);
        return 1;
    }

    /* 2. Persistent per-slot path (~/.melammu_snaps/). */
    {
        const char *home = getenv("HOME");
        if (home)
        {
            snprintf(path, sizeof(path), "%s/.melammu_snaps/melammu_snap_%03d.bgra", home, slot);
            if (swingby_load_snap_file(path, &px, &fw, &fh, &fstride))
            {
                swingby_blit(data, row_pitch, px, fw, fh, fstride);
                return 1;
            }
        }
    }

    return 0;
}

/* ---------- .dat file thumbnail patching (persistence) ----------
 * Called after inject fires.  Builds a 192x108 24-bpp bottom-up BMP from the
 * per-slot BGRA snap, LZSS-compresses it (all-literal mode), and rewrites
 * blob 1 of the CSV2 save container.  The .dat Windows path is read from
 * melammu_inject_dat_path.txt.  Format details: re/FINDINGS.md.
 *
 * The patch runs on a worker thread (CreateThread) — render-thread hooks
 * must never block on file I/O.
 */

#define SWINGBY_BMP_W           192
#define SWINGBY_BMP_H           108
#define SWINGBY_BMP_PIX_BYTES   (SWINGBY_BMP_W * SWINGBY_BMP_H * 3)   /* 62208 */
#define SWINGBY_BMP_TOTAL_BYTES (54 + SWINGBY_BMP_PIX_BYTES)         /* 62262 */

/* LZSS all-literal encoder (same ring-buffer variant as FUN_140068210).
 * Flag byte with n bits set followed by n literal bytes; ~12% overhead. */
static unsigned char *swingby_lzss_all_literal(const unsigned char *src,
                                              size_t src_len, size_t *out_len)
{
    size_t cap = src_len + (src_len / 8) + 8;
    unsigned char *out = HeapAlloc(GetProcessHeap(), 0, cap);
    size_t i = 0, o = 0, n;

    if (!out) { *out_len = 0; return NULL; }
    while (i < src_len)
    {
        n = src_len - i;
        if (n > 8) n = 8;
        out[o++] = (unsigned char)((1u << n) - 1u);
        memcpy(out + o, src + i, n);
        o += n; i += n;
    }
    *out_len = o;
    return out;
}

/* Standalone BGRA snap loader (no shared cache — worker-thread safe). */
static BOOL swingby_load_snap_uncached(const char *path,
    BYTE **out_px, unsigned int *out_fw, unsigned int *out_fh, unsigned int *out_fstride)
{
    unsigned int fw = 0, fh = 0, fstride = 0;
    SIZE_T pix_size;
    BYTE *px;
    FILE *f = fopen(path, "rb");
    if (!f) return FALSE;
    if (fread(&fw,4,1,f) != 1 || fread(&fh,4,1,f) != 1 || fread(&fstride,4,1,f) != 1
        || fw <= 1 || fh <= 1 || fstride < fw * 4)
    { fclose(f); return FALSE; }
    pix_size = (SIZE_T)fstride * fh;
    px = HeapAlloc(GetProcessHeap(), 0, pix_size);
    if (!px || fread(px, 1, pix_size, f) != pix_size)
    {
        if (px) HeapFree(GetProcessHeap(), 0, px);
        fclose(f); return FALSE;
    }
    fclose(f);
    *out_px = px; *out_fw = fw; *out_fh = fh; *out_fstride = fstride;
    return TRUE;
}

static void swingby_patch_dat_file_impl(int slot)
{
    static const char dat_key_path[] = "Z:\\tmp\\melammu_inject_dat_path.txt";

    FILE         *f, *lg;
    BYTE         *raw_px = NULL;
    unsigned int  fw = 0, fh = 0, fstride = 0;
    char          dat_path[1024] = {0};
    char          snap_path[512];
    BYTE         *dat = NULL, *new_dat = NULL, *bmp = NULL;
    unsigned char *lzss = NULL;
    long          dat_size = 0;
    size_t        new_total, lzss_len = 0;
    UINT32        cs0 = 0, cs1 = 0, cs2 = 0;
    size_t        blob0_off, blob1_off, blob2_off, checksum_off;
    int           dy, dx, n;
    UINT32        v_u32;
    INT32         v_i32;
    UINT16        v_u16;

    /* 1. Load per-slot snap.  /tmp first, then persistent fallback. */
    snprintf(snap_path, sizeof(snap_path), "Z:\\tmp\\melammu_snap_%03d.bgra", slot);
    if (!swingby_load_snap_uncached(snap_path, &raw_px, &fw, &fh, &fstride))
    {
        const char *home = getenv("HOME");
        if (home)
        {
            snprintf(snap_path, sizeof(snap_path),
                     "%s/.melammu_snaps/melammu_snap_%03d.bgra", home, slot);
            if (!swingby_load_snap_uncached(snap_path, &raw_px, &fw, &fh, &fstride))
                raw_px = NULL;
        }
    }
    if (!raw_px)
    {
        lg = fopen("Z:\\tmp\\swingby_patch_dbg.txt","w");
        if (lg) { fprintf(lg,"no snap for slot %d\n", slot); fclose(lg); }
        return;
    }

    /* 2. Resolve .dat path. */
    f = fopen(dat_key_path, "r");
    if (f)
    {
        if (fgets(dat_path, sizeof(dat_path), f))
        {
            n = (int)strlen(dat_path);
            while (n > 0 && (dat_path[n-1]=='\n'||dat_path[n-1]=='\r'||dat_path[n-1]==' '))
                dat_path[--n] = '\0';
        }
        fclose(f);
    }
    if (!dat_path[0])
    {
        char exe_buf[512]; char *sep;
        if (GetModuleFileNameA(NULL, exe_buf, sizeof(exe_buf))
            && (sep = strrchr(exe_buf, '\\')))
        {
            *sep = '\0';
            snprintf(dat_path, sizeof(dat_path), "%s\\save\\save%03d.dat", exe_buf, slot);
        }
    }
    if (!dat_path[0])
    {
        lg = fopen("Z:\\tmp\\swingby_patch_dbg.txt","w");
        if (lg) { fprintf(lg,"no dat path\n"); fclose(lg); }
        HeapFree(GetProcessHeap(), 0, raw_px);
        return;
    }

    /* 3. Read whole .dat file. */
    f = fopen(dat_path, "rb");
    if (!f)
    {
        lg = fopen("Z:\\tmp\\swingby_patch_dbg.txt","w");
        if (lg) { fprintf(lg,"open failed: %s\n", dat_path); fclose(lg); }
        HeapFree(GetProcessHeap(), 0, raw_px);
        return;
    }
    fseek(f, 0, SEEK_END);
    dat_size = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (dat_size < 0x260
        || !(dat = HeapAlloc(GetProcessHeap(), 0, (SIZE_T)dat_size))
        || fread(dat, 1, dat_size, f) != (size_t)dat_size)
    {
        fclose(f);
        if (dat) HeapFree(GetProcessHeap(), 0, dat);
        HeapFree(GetProcessHeap(), 0, raw_px);
        lg = fopen("Z:\\tmp\\swingby_patch_dbg.txt","w");
        if (lg) { fprintf(lg,"read failed: %s sz=%ld\n", dat_path, dat_size); fclose(lg); }
        return;
    }
    fclose(f);

    /* 4. Validate magic and extract blob layout. */
    if (dat[0] != 'C' || dat[1] != 'S' || dat[2] != 'V' || dat[3] != '2')
    {
        lg = fopen("Z:\\tmp\\swingby_patch_dbg.txt","w");
        if (lg) { fprintf(lg,"not CSV2: %s\n", dat_path); fclose(lg); }
        HeapFree(GetProcessHeap(), 0, dat);
        HeapFree(GetProcessHeap(), 0, raw_px);
        return;
    }
    memcpy(&cs0, dat + 0x230, 4);
    memcpy(&cs1, dat + 0x234, 4);
    memcpy(&cs2, dat + 0x238, 4);
    blob0_off    = 0x258;
    blob1_off    = blob0_off + cs0;
    blob2_off    = blob1_off + cs1;
    checksum_off = blob2_off + cs2;
    if (checksum_off + 2 > (size_t)dat_size)
    {
        lg = fopen("Z:\\tmp\\swingby_patch_dbg.txt","w");
        if (lg) { fprintf(lg,"layout OOB cs0=%u cs1=%u cs2=%u datsz=%ld\n",
                              cs0, cs1, cs2, dat_size); fclose(lg); }
        HeapFree(GetProcessHeap(), 0, dat);
        HeapFree(GetProcessHeap(), 0, raw_px);
        return;
    }

    /* 5. Build 192x108 24-bpp BMP (bottom-up BGR) from top-down BGRA snap.
     * 192*3 = 576 bytes/row, already 4-byte aligned (no row padding needed). */
    bmp = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, SWINGBY_BMP_TOTAL_BYTES);
    if (!bmp)
    {
        HeapFree(GetProcessHeap(), 0, dat);
        HeapFree(GetProcessHeap(), 0, raw_px);
        return;
    }

    bmp[0] = 'B'; bmp[1] = 'M';
    v_u32 = SWINGBY_BMP_TOTAL_BYTES; memcpy(bmp +  2, &v_u32, 4); /* file size */
    /* reserved (offset 6, 4 bytes) = 0 */
    v_u32 = 54;                     memcpy(bmp + 10, &v_u32, 4); /* pixel data offset */
    v_u32 = 40;                     memcpy(bmp + 14, &v_u32, 4); /* DIB header size */
    v_i32 = SWINGBY_BMP_W;           memcpy(bmp + 18, &v_i32, 4); /* width */
    v_i32 = SWINGBY_BMP_H;           memcpy(bmp + 22, &v_i32, 4); /* height (positive = bottom-up) */
    v_u16 = 1;                      memcpy(bmp + 26, &v_u16, 2); /* planes */
    v_u16 = 24;                     memcpy(bmp + 28, &v_u16, 2); /* bpp */
    /* compression (offset 30, BI_RGB = 0) already zero */
    v_u32 = SWINGBY_BMP_PIX_BYTES;   memcpy(bmp + 34, &v_u32, 4); /* raw image size */
    /* x/y ppm, colors_used, important_colors at 38..50 already zero */

    /* BMP row r (0 = bottom) ← visual row (BMP_H-1-r), nearest-neighbor scaled. */
    for (dy = 0; dy < SWINGBY_BMP_H; dy++)
    {
        unsigned int visual_row = (unsigned int)(SWINGBY_BMP_H - 1 - dy);
        unsigned int sy = (unsigned int)((UINT64)visual_row * fh / SWINGBY_BMP_H);
        const BYTE *src_row = raw_px + (SIZE_T)sy * fstride;
        BYTE *dst_row = bmp + 54 + (SIZE_T)dy * (SWINGBY_BMP_W * 3);
        for (dx = 0; dx < SWINGBY_BMP_W; dx++)
        {
            unsigned int sx = (unsigned int)((UINT64)dx * fw / SWINGBY_BMP_W);
            const BYTE *sp = src_row + sx * 4;
            BYTE *dp = dst_row + dx * 3;
            dp[0] = sp[0]; /* B */
            dp[1] = sp[1]; /* G */
            dp[2] = sp[2]; /* R */
        }
    }
    HeapFree(GetProcessHeap(), 0, raw_px);

    /* 6. LZSS-encode the BMP. */
    lzss = swingby_lzss_all_literal(bmp, SWINGBY_BMP_TOTAL_BYTES, &lzss_len);
    HeapFree(GetProcessHeap(), 0, bmp);
    if (!lzss) { HeapFree(GetProcessHeap(), 0, dat); return; }

    /* 7. Reassemble: 0x258 header + blob0 + new_blob1 + blob2 + 2-byte checksum. */
    new_total = blob0_off + cs0 + lzss_len + cs2 + 2;
    new_dat = HeapAlloc(GetProcessHeap(), 0, new_total);
    if (!new_dat)
    {
        HeapFree(GetProcessHeap(), 0, lzss);
        HeapFree(GetProcessHeap(), 0, dat);
        return;
    }
    memcpy(new_dat, dat, blob0_off);

    /* Header patches: total body size (0x21C), new blob-1 comp/raw (0x234/0x248). */
    v_u32 = cs0 + (UINT32)lzss_len + cs2; memcpy(new_dat + 0x21C, &v_u32, 4);
    v_u32 = (UINT32)lzss_len;             memcpy(new_dat + 0x234, &v_u32, 4);
    v_u32 = (UINT32)SWINGBY_BMP_TOTAL_BYTES; memcpy(new_dat + 0x248, &v_u32, 4);

    memcpy(new_dat + blob0_off,                       dat + blob0_off,    cs0);
    memcpy(new_dat + blob0_off + cs0,                 lzss,               lzss_len);
    memcpy(new_dat + blob0_off + cs0 + lzss_len,      dat + blob2_off,    cs2);
    memcpy(new_dat + blob0_off + cs0 + lzss_len + cs2,
                                                      dat + checksum_off, 2);

    HeapFree(GetProcessHeap(), 0, lzss);

    /* 8. Write back (full rewrite). */
    f = fopen(dat_path, "wb");
    if (!f)
    {
        lg = fopen("Z:\\tmp\\swingby_patch_dbg.txt","w");
        if (lg) { fprintf(lg, "open-for-write failed: %s\n", dat_path); fclose(lg); }
    }
    else
    {
        size_t wrote = fwrite(new_dat, 1, new_total, f);
        fclose(f);
        lg = fopen("Z:\\tmp\\swingby_patch_dbg.txt","w");
        if (lg) { fprintf(lg, "patch slot=%d %s old_cs1=%u new_cs1=%lu total=%lu wrote=%lu\n",
                              slot, dat_path, cs1, (unsigned long)lzss_len, (unsigned long)new_total, (unsigned long)wrote); fclose(lg); }
    }

    HeapFree(GetProcessHeap(), 0, new_dat);
    HeapFree(GetProcessHeap(), 0, dat);
}

/* Worker thread entry point — runs swingby_patch_dat_file_impl off the render thread. */
static DWORD WINAPI swingby_patch_dat_thread(LPVOID arg)
{
    int slot = (int)(INT_PTR)arg;
    swingby_patch_dat_file_impl(slot);
    return 0;
}

/* Render-thread-safe entry point.  Spawns a worker and returns immediately. */
static void swingby_patch_dat_file(int slot)
{
    HANDLE h;
    if (slot < 0) return;
    h = CreateThread(NULL, 0, swingby_patch_dat_thread, (LPVOID)(INT_PTR)slot, 0, NULL);
    if (h) CloseHandle(h);
}

/* State for counter-based 192x108 thumbnail injection. */
static DWORD              s_192_last_tick    = 0;
static int                s_192_counter      = 0;
/* Pending UnlockRect injection: write snap AFTER game fills the surface. */
static IDirect3DSurface9 *s_unlock_iface     = NULL;
static void              *s_unlock_data      = NULL;
static unsigned int       s_unlock_pitch     = 0;
static int                s_unlock_slot      = -1;
static IDirect3DSurface9 *s_shadow_lock_iface = NULL;
static IDirect3DSurface9 *s_shadow_lock_surface = NULL;
static BYTE              *s_last_good_frame = NULL;
static unsigned int       s_last_good_width = 0;
static unsigned int       s_last_good_height = 0;
static unsigned int       s_last_good_stride = 0;
static DWORD              s_last_good_tick = 0;
static unsigned long      s_last_good_avg = 0;

static unsigned long swingby_log_lock_sample(const char *tag, IDirect3DSurface9 *iface,
        const struct wined3d_sub_resource_desc *desc, const RECT *rect,
        DWORD flags, const struct wined3d_map_desc *map_desc)
{
    unsigned int sample_w, sample_h, step_x, step_y, x, y, count = 0;
    unsigned int min_y = 255, max_y = 0;
    UINT64 sum_y = 0;
    FILE *lg;

    if (!map_desc->data || !map_desc->row_pitch || desc->width < 16 || desc->height < 16
            || map_desc->row_pitch < desc->width * 4)
        return (unsigned long)-1;

    sample_w = desc->width < 192 ? desc->width : 192;
    sample_h = desc->height < 108 ? desc->height : 108;
    step_x = sample_w / 16;
    step_y = sample_h / 12;
    if (!step_x) step_x = 1;
    if (!step_y) step_y = 1;

    for (y = 0; y < sample_h; y += step_y)
    {
        const BYTE *row = (const BYTE *)map_desc->data + (SIZE_T)y * map_desc->row_pitch;
        for (x = 0; x < sample_w; x += step_x)
        {
            const BYTE *p = row + x * 4;
            unsigned int lum = ((unsigned int)p[0] + p[1] + p[2]) / 3;
            if (lum < min_y) min_y = lum;
            if (lum > max_y) max_y = lum;
            sum_y += lum;
            count++;
        }
    }

    lg = fopen("Z:\\tmp\\swingby_lock_detail.txt", "a");
    if (lg)
    {
        fprintf(lg,
                "%s surf=%p %ux%u rect=%s flags=0x%lx acc=0x%x bind=0x%x fmt=0x%x pitch=%u avg=%lu min=%u max=%u samples=%u\n",
                tag, (void *)iface, desc->width, desc->height, wine_dbgstr_rect(rect),
                (unsigned long)flags, desc->access, desc->bind_flags, desc->format,
                map_desc->row_pitch, count ? (unsigned long)(sum_y / count) : 0,
                min_y, max_y, count);
        fclose(lg);
    }

    return count ? (unsigned long)(sum_y / count) : (unsigned long)-1;
}

/* Diag: read the surface's current GPU content through an independent
 * blt -> sysmem path and report its luminance.  Distinguishes "content exists
 * on the GPU but the CPU map is stale/black" from "the surface really has no
 * content at lock time". */
static void swingby_probe_gpu_content(IDirect3DSurface9 *iface, struct d3d9_surface *surface,
        const struct wined3d_sub_resource_desc *desc)
{
    IDirect3DSurface9 *probe = NULL;
    struct d3d9_surface *probe_impl;
    struct wined3d_map_desc map_desc;
    D3DFORMAT d3d_format = d3dformat_from_wined3dformat(desc->format);
    RECT r;
    HRESULT hr;

    swingby_rt_capture_active = TRUE;

    hr = IDirect3DDevice9Ex_CreateOffscreenPlainSurface(surface->parent_device,
            desc->width, desc->height, d3d_format, D3DPOOL_SYSTEMMEM, &probe, NULL);
    if (SUCCEEDED(hr))
    {
        struct d3d9_device *device = CONTAINING_RECORD(surface->parent_device,
                struct d3d9_device, IDirect3DDevice9Ex_iface);
        probe_impl = unsafe_impl_from_IDirect3DSurface9(probe);
        SetRect(&r, 0, 0, desc->width, desc->height);

        wined3d_mutex_lock();
        hr = wined3d_device_context_blt(device->immediate_context,
                probe_impl->wined3d_texture, probe_impl->sub_resource_idx, &r,
                surface->wined3d_texture, surface->sub_resource_idx, &r,
                0, NULL, WINED3D_TEXF_POINT);
        wined3d_mutex_unlock();

        if (SUCCEEDED(hr)
                && SUCCEEDED(wined3d_resource_map(wined3d_texture_get_resource(probe_impl->wined3d_texture),
                        probe_impl->sub_resource_idx, &map_desc, NULL, WINED3D_MAP_READ)))
        {
            unsigned long avg = swingby_log_lock_sample("DIAG_GPU_PROBE", iface, desc, NULL, 0, &map_desc);
            swingby_diag("GPU_PROBE surf=%p %ux%u blt_avg=%lu",
                    (void *)iface, desc->width, desc->height, avg);
            wined3d_resource_unmap(wined3d_texture_get_resource(probe_impl->wined3d_texture),
                    probe_impl->sub_resource_idx);
        }
        else
            swingby_diag("GPU_PROBE surf=%p blt/map failed hr=0x%lx",
                    (void *)iface, (unsigned long)hr);
        IDirect3DSurface9_Release(probe);
    }
    else
        swingby_diag("GPU_PROBE surf=%p create failed hr=0x%lx",
                (void *)iface, (unsigned long)hr);

    swingby_rt_capture_active = FALSE;
}

/* Diag: most recent full-resolution write lock, sampled again at UnlockRect to
 * see what content the application itself wrote into the surface. */
static IDirect3DSurface9 *s_diag_write_iface;
static void *s_diag_write_data;
static unsigned int s_diag_write_pitch;
static struct wined3d_sub_resource_desc s_diag_write_desc;

/* ---- Windows windowed-present copy semantics --------------------------
 * On Windows, presenting in windowed mode leaves the presented frame in the
 * back buffer.  CMVS captures save/load thumbnails with GetBackBuffer +
 * LockRect(READONLY) at the moment the save/load screen opens, expecting
 * that frame to still be there.  On the Metal-backed wined3d path the
 * back-buffer content is gone after Present (the diag GPU probe reads black
 * even through an independent blt).  Emulate the Windows semantics instead:
 * device.c stores a copy of the back buffer at every Present, and the
 * READONLY back-buffer lock serves that copy verbatim — no luminance
 * heuristics, no freshness windows, no snap files. */
static BYTE        *s_lastpres_frame;
static unsigned int s_lastpres_w, s_lastpres_h, s_lastpres_stride;

void swingby_store_last_presented(const void *data, unsigned int pitch,
        unsigned int w, unsigned int h)
{
    SIZE_T row_bytes = (SIZE_T)w * 4;
    unsigned int y;

    if (!data || !w || !h || pitch < row_bytes)
        return;
    if (!s_lastpres_frame || s_lastpres_w != w || s_lastpres_h != h)
    {
        BYTE *nf = s_lastpres_frame
            ? HeapReAlloc(GetProcessHeap(), 0, s_lastpres_frame, row_bytes * h)
            : HeapAlloc(GetProcessHeap(), 0, row_bytes * h);
        if (!nf)
            return;
        s_lastpres_frame = nf;
        s_lastpres_w = w;
        s_lastpres_h = h;
        s_lastpres_stride = (unsigned int)row_bytes;
    }
    for (y = 0; y < h; y++)
        memcpy(s_lastpres_frame + (SIZE_T)y * s_lastpres_stride,
                (const BYTE *)data + (SIZE_T)y * pitch, row_bytes);
}

static void swingby_remember_last_good_frame(const struct wined3d_sub_resource_desc *desc,
        DWORD flags, const struct wined3d_map_desc *map_desc, unsigned long avg)
{
    SIZE_T row_bytes = (SIZE_T)desc->width * 4;
    SIZE_T frame_bytes = row_bytes * desc->height;
    unsigned int y;
    BYTE *new_frame;
    FILE *lg;

    if (!(flags & D3DLOCK_READONLY))
        return;
    if (desc->width != 1280 || desc->height != 720 || desc->access != 0xe || desc->bind_flags)
        return;
    if (avg == (unsigned long)-1 || avg < 16)
        return;
    if (!map_desc->data || map_desc->row_pitch < row_bytes)
        return;

    if (!s_last_good_frame || s_last_good_width != desc->width
            || s_last_good_height != desc->height || s_last_good_stride != row_bytes)
    {
        if (s_last_good_frame)
            new_frame = HeapReAlloc(GetProcessHeap(), 0, s_last_good_frame, frame_bytes);
        else
            new_frame = HeapAlloc(GetProcessHeap(), 0, frame_bytes);
        if (!new_frame)
            return;
        s_last_good_frame = new_frame;
        s_last_good_width = desc->width;
        s_last_good_height = desc->height;
        s_last_good_stride = row_bytes;
    }

    for (y = 0; y < desc->height; y++)
        memcpy(s_last_good_frame + (SIZE_T)y * s_last_good_stride,
                (const BYTE *)map_desc->data + (SIZE_T)y * map_desc->row_pitch, row_bytes);

    s_last_good_tick = GetTickCount();
    s_last_good_avg = avg;

    lg = fopen("Z:\\tmp\\swingby_lock_detail.txt", "a");
    if (lg)
    {
        fprintf(lg, "LAST_GOOD_FRAME 1280x720 avg=%lu tick=%lu active=%u\n",
                s_last_good_avg, (unsigned long)s_last_good_tick, swingby_rt_capture_active);
        fclose(lg);
    }
}

static void swingby_write_last_good_snap_file(void)
{
    static const char snap_out[] = "Z:\\tmp\\melammu_snap.bgra";
    uint32_t w, h, s;
    unsigned int y;
    FILE *f;
    FILE *lg;

    if (!s_last_good_frame || !s_last_good_width || !s_last_good_height || !s_last_good_stride)
        return;

    f = fopen(snap_out, "wb");
    if (!f)
        return;

    w = s_last_good_width;
    h = s_last_good_height;
    s = s_last_good_stride;
    fwrite(&w, 4, 1, f);
    fwrite(&h, 4, 1, f);
    fwrite(&s, 4, 1, f);
    for (y = 0; y < s_last_good_height; y++)
        fwrite(s_last_good_frame + (SIZE_T)y * s_last_good_stride,
                s_last_good_width * 4, 1, f);
    fclose(f);

    melammu_snap_tick = GetTickCount();

    lg = fopen("Z:\\tmp\\swingby_lock_detail.txt", "a");
    if (lg)
    {
        fprintf(lg, "SNAP_FROM_LAST_GOOD 1280x720 avg=%lu tick=%lu\n",
                s_last_good_avg, (unsigned long)melammu_snap_tick);
        fclose(lg);
    }
}

static BOOL swingby_fill_shadow_from_last_good(IDirect3DSurface9 *iface,
        const struct wined3d_sub_resource_desc *desc, const RECT *rect,
        DWORD flags, const struct wined3d_map_desc *map_desc, unsigned long avg)
{
    DWORD now = GetTickCount();
    DWORD max_age = swingby_save_screen_cooldown ? 120000 : 5000;
    SIZE_T row_bytes = (SIZE_T)desc->width * 4;
    unsigned int y;
    FILE *lg;

    if (avg == (unsigned long)-1 || avg > 4)
        return FALSE;
    if (!s_last_good_frame || !s_last_good_tick || (DWORD)(now - s_last_good_tick) > max_age)
    {
        lg = fopen("Z:\\tmp\\swingby_lock_detail.txt", "a");
        if (lg)
        {
            fprintf(lg,
                    "LOCK_SHADOW_FILL_SKIP no_recent_last_good surf=%p age=%lu max_age=%lu cooldown=%u has=%u tick=%lu avg_before=%lu\n",
                    (void *)iface, s_last_good_tick ? (unsigned long)(now - s_last_good_tick) : 0,
                    (unsigned long)max_age, swingby_save_screen_cooldown,
                    s_last_good_frame ? 1 : 0, (unsigned long)s_last_good_tick, avg);
            fclose(lg);
        }
        return FALSE;
    }
    if (desc->width != s_last_good_width || desc->height != s_last_good_height
            || row_bytes != s_last_good_stride)
    {
        lg = fopen("Z:\\tmp\\swingby_lock_detail.txt", "a");
        if (lg)
        {
            fprintf(lg,
                    "LOCK_SHADOW_FILL_SKIP size_mismatch surf=%p shadow=%ux%u cached=%ux%u stride=%u/%u avg_before=%lu\n",
                    (void *)iface, desc->width, desc->height, s_last_good_width, s_last_good_height,
                    (unsigned int)row_bytes, s_last_good_stride, avg);
            fclose(lg);
        }
        return FALSE;
    }
    if (!map_desc->data || map_desc->row_pitch < row_bytes)
        return FALSE;

    for (y = 0; y < desc->height; y++)
        memcpy((BYTE *)map_desc->data + (SIZE_T)y * map_desc->row_pitch,
                s_last_good_frame + (SIZE_T)y * s_last_good_stride, row_bytes);

    lg = fopen("Z:\\tmp\\swingby_lock_detail.txt", "a");
    if (lg)
    {
        fprintf(lg,
                "LOCK_SHADOW_FILL_LAST_GOOD surf=%p rect=%s flags=0x%lx age=%lu avg_before=%lu avg_cached=%lu\n",
                (void *)iface, wine_dbgstr_rect(rect), (unsigned long)flags,
                (unsigned long)(now - s_last_good_tick), avg, s_last_good_avg);
        fclose(lg);
    }
    swingby_write_last_good_snap_file();
    return TRUE;
}

static HRESULT WINAPI d3d9_surface_LockRect(IDirect3DSurface9 *iface,
        D3DLOCKED_RECT *locked_rect, const RECT *rect, DWORD flags)
{
    struct d3d9_surface *surface = impl_from_IDirect3DSurface9(iface);
    struct wined3d_sub_resource_desc desc;
    struct wined3d_box box;
    struct wined3d_map_desc map_desc;
    HRESULT hr;

    TRACE("iface %p, locked_rect %p, rect %s, flags %#lx.\n",
            iface, locked_rect, wine_dbgstr_rect(rect), flags);
    if (rect)
        wined3d_box_set(&box, rect->left, rect->top, rect->right, rect->bottom, 0, 1);

    wined3d_mutex_lock();
    wined3d_texture_get_sub_resource_desc(surface->wined3d_texture, surface->sub_resource_idx, &desc);
    wined3d_mutex_unlock();

    /* Diag: full-resolution locks are the save-thumbnail readback candidates.
     * Log them all, and for read-only locks also probe the GPU-side content
     * through an independent blt so map-vs-GPU divergence is visible. */
    if (!swingby_rt_capture_active && desc.width >= 640 && desc.height >= 400)
    {
        swingby_diag("LockRect surf=%p %ux%u flags=0x%lx acc=0x%x bind=0x%x rect=%s",
                (void *)iface, desc.width, desc.height, (unsigned long)flags,
                desc.access, desc.bind_flags, rect ? "sub" : "full");
        if (swingby_observe_only && (flags & D3DLOCK_READONLY))
            swingby_probe_gpu_content(iface, surface, &desc);
    }

    /* Retired 2026-06-11: the sysmem-shadow + last-good-fill route is
     * superseded by the last-presented back-buffer serve below, which
     * reproduces Windows windowed-present copy semantics exactly.  Kept for
     * reference until the fix is user-verified. */
    if (0
            && (flags & D3DLOCK_READONLY)
            && !swingby_rt_capture_active
            && !s_shadow_lock_surface
            && desc.access == (WINED3D_RESOURCE_ACCESS_GPU
                    | WINED3D_RESOURCE_ACCESS_MAP_R | WINED3D_RESOURCE_ACCESS_MAP_W)
            && desc.width >= 640 && desc.height >= 400)
    {
        IDirect3DSurface9 *shadow = NULL;
        struct d3d9_surface *shadow_impl;
        struct d3d9_device *device = CONTAINING_RECORD(surface->parent_device,
                struct d3d9_device, IDirect3DDevice9Ex_iface);
        RECT full_rect;
        D3DFORMAT d3d_format = d3dformat_from_wined3dformat(desc.format);

        {
            FILE *lg = fopen("Z:\\tmp\\swingby_lock.txt","a");
            if (lg)
            {
                fprintf(lg,
                        "LOCK_SHADOW_CANDIDATE src=%p %ux%u rect=%s flags=0x%lx acc=0x%x bind=0x%x fmt=0x%x d3dfmt=0x%x\n",
                        (void *)iface, desc.width, desc.height, wine_dbgstr_rect(rect),
                        (unsigned long)flags, desc.access, desc.bind_flags, desc.format, d3d_format);
                fclose(lg);
            }
        }

        hr = IDirect3DDevice9Ex_CreateOffscreenPlainSurface(surface->parent_device,
                desc.width, desc.height, d3d_format, D3DPOOL_SYSTEMMEM, &shadow, NULL);
        if (SUCCEEDED(hr))
        {
            shadow_impl = unsafe_impl_from_IDirect3DSurface9(shadow);
            SetRect(&full_rect, 0, 0, desc.width, desc.height);

            wined3d_mutex_lock();
            hr = wined3d_device_context_blt(device->immediate_context,
                    shadow_impl->wined3d_texture, shadow_impl->sub_resource_idx, &full_rect,
                    surface->wined3d_texture, surface->sub_resource_idx, &full_rect,
                    0, NULL, WINED3D_TEXF_POINT);
            wined3d_mutex_unlock();

            if (SUCCEEDED(hr))
            {
                hr = wined3d_resource_map(wined3d_texture_get_resource(shadow_impl->wined3d_texture),
                        shadow_impl->sub_resource_idx, &map_desc, rect ? &box : NULL,
                        wined3dmapflags_from_d3dmapflags(flags, 0));
                if (SUCCEEDED(hr))
                {
                    unsigned long avg = swingby_log_lock_sample("LOCK_SHADOW_SAMPLE", iface, &desc, rect, flags, &map_desc);
                    if (swingby_fill_shadow_from_last_good(iface, &desc, rect, flags, &map_desc, avg))
                        swingby_log_lock_sample("LOCK_SHADOW_SAMPLE_AFTER_FILL", iface, &desc, rect, flags, &map_desc);
                    locked_rect->Pitch = map_desc.row_pitch;
                    locked_rect->pBits = map_desc.data;
                    s_shadow_lock_iface = iface;
                    s_shadow_lock_surface = shadow;
                    {
                        FILE *lg = fopen("Z:\\tmp\\swingby_lock.txt","a");
                        if (lg)
                        {
                            fprintf(lg,
                                    "LOCK_SHADOW_RT src=%p shadow=%p %ux%u rect=%s flags=0x%lx acc=0x%x bind=0x%x pitch=%u\n",
                                    (void *)iface, (void *)shadow, desc.width, desc.height,
                                    wine_dbgstr_rect(rect), (unsigned long)flags, desc.access, desc.bind_flags,
                                    map_desc.row_pitch);
                            fclose(lg);
                        }
                    }
                    return D3D_OK;
                }
            }

            {
                FILE *lg = fopen("Z:\\tmp\\swingby_lock.txt","a");
                if (lg)
                {
                    fprintf(lg,
                            "LOCK_SHADOW_RT_FAIL src=%p %ux%u rect=%s flags=0x%lx hr=0x%08lx\n",
                            (void *)iface, desc.width, desc.height,
                            wine_dbgstr_rect(rect), (unsigned long)flags, (unsigned long)hr);
                    fclose(lg);
                }
            }
            IDirect3DSurface9_Release(shadow);
        }
        else
        {
            FILE *lg = fopen("Z:\\tmp\\swingby_lock.txt","a");
            if (lg)
            {
                fprintf(lg,
                        "LOCK_SHADOW_CREATE_FAIL src=%p %ux%u rect=%s flags=0x%lx acc=0x%x bind=0x%x fmt=0x%x d3dfmt=0x%x hr=0x%08lx\n",
                        (void *)iface, desc.width, desc.height, wine_dbgstr_rect(rect),
                        (unsigned long)flags, desc.access, desc.bind_flags, desc.format, d3d_format, (unsigned long)hr);
                fclose(lg);
            }
        }
    }

    hr = wined3d_resource_map(wined3d_texture_get_resource(surface->wined3d_texture), surface->sub_resource_idx,
            &map_desc, rect ? &box : NULL, wined3dmapflags_from_d3dmapflags(flags, 0));

    if (SUCCEEDED(hr))
    {
        locked_rect->Pitch = map_desc.row_pitch;
        locked_rect->pBits = map_desc.data;

        /* Melammu CMVS save-thumbnail capture: only when explicitly enabled by
         * the launcher (MELAMMU_CMVS_THUMBS=1).  When OFF this whole block is
         * skipped so LockRect is byte-for-byte stock wine — required so the
         * last-presented serve below never corrupts non-CMVS games' back-buffer
         * READONLY locks (the KiriKiri Z white-screen). */
        if (swingby_capture_is_enabled())
        {
        /* Windows windowed-present copy semantics: a READONLY lock of the
         * implicit swapchain's back buffer returns the last presented frame.
         * The native map is black on the Metal path, so fill it from the
         * per-Present copy taken in swingby_capture_frontbuffer().  CMVS locks
         * with an explicit full-surface rect; map_desc.data then points at
         * the rect origin, so copy with the rect offset applied. */
        if ((flags & D3DLOCK_READONLY) && !swingby_rt_capture_active
                && map_desc.data && s_lastpres_frame
                && desc.width == s_lastpres_w && desc.height == s_lastpres_h
                && (desc.bind_flags & WINED3D_BIND_RENDER_TARGET))
        {
            unsigned int x0 = rect ? rect->left : 0;
            unsigned int y0 = rect ? rect->top : 0;
            unsigned int cw = rect ? (unsigned int)(rect->right - rect->left) : desc.width;
            unsigned int ch = rect ? (unsigned int)(rect->bottom - rect->top) : desc.height;

            if (cw && ch && x0 + cw <= s_lastpres_w && y0 + ch <= s_lastpres_h
                    && map_desc.row_pitch >= cw * 4)
            {
                struct d3d9_device *device = CONTAINING_RECORD(surface->parent_device,
                        struct d3d9_device, IDirect3DDevice9Ex_iface);
                struct wined3d_texture *bb_texture = NULL;

                wined3d_mutex_lock();
                if (device->implicit_swapchain_count)
                    bb_texture = wined3d_swapchain_get_back_buffer(device->implicit_swapchains[0], 0);
                wined3d_mutex_unlock();

                if (bb_texture && surface->wined3d_texture == bb_texture && !surface->sub_resource_idx)
                {
                    unsigned int y;
                    for (y = 0; y < ch; y++)
                        memcpy((BYTE *)map_desc.data + (SIZE_T)y * map_desc.row_pitch,
                                s_lastpres_frame + (SIZE_T)(y0 + y) * s_lastpres_stride + (SIZE_T)x0 * 4,
                                (SIZE_T)cw * 4);
                    swingby_diag("BB_SERVE_LAST_PRESENTED surf=%p rect=(%u,%u %ux%u)",
                            (void *)iface, x0, y0, cw, ch);
                }
            }
        }

        /* Log ALL LockRect calls (size + flags) to identify CMVS's capture path. */
        if (map_desc.data)
        {
            { static DWORD s_lr_throttle = 0; DWORD _now = GetTickCount();
              if (!swingby_rt_capture_active
                  && (desc.width != 192 || desc.height != 108) && (DWORD)(_now - s_lr_throttle) > 200) {
                FILE *lg2 = fopen("Z:\\tmp\\swingby_lock.txt","a");
                if (lg2) { fprintf(lg2,"LockRect %ux%u flags=0x%lx acc=0x%x\n",
                    desc.width,desc.height,(unsigned long)flags,desc.access); fclose(lg2); s_lr_throttle=_now; } } }

            /* CMVS locks the full-resolution GetRenderTargetData destination
             * surface to encode the save thumbnail.  Do not overwrite it from an
             * external snap here; Windows semantics are established by the direct
             * render_target -> dst_surface copy in device.c.  This log ties the
             * LockRect back to the exact GetRenderTargetData destination. */
            {
                DWORD lock_now = GetTickCount();
                BOOL capture_access = (desc.access == 0xd) || (desc.access == 0xe);

                if ((flags & 0x10) /* D3DLOCK_READONLY */
                    && !swingby_rt_capture_active
                    && capture_access
                    && (desc.width >= 640) && (desc.height >= 400))
                {
                    BOOL matched = iface == s_rtdata_dst_surf
                        && s_rtdata_tick
                        && (DWORD)(lock_now - s_rtdata_tick) < 5000;
                    if (matched && !s_rtdata_lock_logged)
                    {
                        FILE *lg = fopen("Z:\\tmp\\swingby_lock.txt","a");
                        if (lg)
                        {
                            fprintf(lg,
                                "LOCK_RTDATA_MATCH serial=%u src=%p dst=%p %ux%u flags=0x%lx acc=0x%x pitch=%u age=%lu\n",
                                s_rtdata_serial,(void*)s_rtdata_src_surf,(void*)iface,
                                desc.width,desc.height,(unsigned long)flags,desc.access,
                                map_desc.row_pitch,(unsigned long)(lock_now - s_rtdata_tick));
                            fclose(lg);
                        }
                        s_rtdata_lock_logged = TRUE;
                    }
                }
            }

            if (desc.width == 192 && desc.height == 108)
            {
                /* Tell device.c to pause auto-capture: save screen is open. */
                swingby_save_screen_cooldown = 1800; /* ~30s at 60fps; keep the pre-save gameplay snap */

                /* The old per-slot preview injection counted 192x108 LockRect calls
                 * and mapped them to save slots.  CMVS does not render slots in a
                 * stable enough order, so reopening the save screen could shift
                 * thumbnails between slots.  Leave preview surfaces untouched and
                 * rely on the saved .dat thumbnail produced by the full-resolution
                 * capture path above. */
            }

            if (desc.width >= 640 && desc.height >= 400 && !swingby_rt_capture_active)
            {
                unsigned long avg = swingby_log_lock_sample("LOCK_SAMPLE", iface, &desc, rect, flags, &map_desc);
                swingby_diag("LOCK_MAP surf=%p flags=0x%lx map_avg=%lu",
                        (void *)iface, (unsigned long)flags, avg);
                if (!(flags & D3DLOCK_READONLY))
                {
                    /* Write lock: sample again at UnlockRect to see what the
                     * application wrote into this surface. */
                    s_diag_write_iface = iface;
                    s_diag_write_data  = map_desc.data;
                    s_diag_write_pitch = map_desc.row_pitch;
                    s_diag_write_desc  = desc;
                }
                if (!swingby_observe_only)
                    swingby_remember_last_good_frame(&desc, flags, &map_desc, avg);
            }
            else if (desc.width == 192 && desc.height == 108)
            {
                static DWORD s_l192_throttle;
                DWORD now192 = GetTickCount();
                if ((DWORD)(now192 - s_l192_throttle) > 250)
                {
                    unsigned long avg = swingby_log_lock_sample("LOCK_SAMPLE", iface, &desc, rect, flags, &map_desc);
                    s_l192_throttle = now192;
                    swingby_diag("LOCK_192 surf=%p flags=0x%lx avg=%lu",
                            (void *)iface, (unsigned long)flags, avg);
                }
            }
        }
        } /* end if (swingby_capture_is_enabled()) */
    }

    if (hr == E_INVALIDARG)
        return D3DERR_INVALIDCALL;
    return hr;
}

static HRESULT WINAPI d3d9_surface_UnlockRect(IDirect3DSurface9 *iface)
{
    struct d3d9_surface *surface = impl_from_IDirect3DSurface9(iface);
    HRESULT hr;

    TRACE("iface %p.\n", iface);

    if (iface == s_shadow_lock_iface && s_shadow_lock_surface)
    {
        struct d3d9_surface *shadow = unsafe_impl_from_IDirect3DSurface9(s_shadow_lock_surface);

        wined3d_mutex_lock();
        hr = wined3d_resource_unmap(wined3d_texture_get_resource(shadow->wined3d_texture),
                shadow->sub_resource_idx);
        wined3d_mutex_unlock();

        {
            FILE *lg = fopen("Z:\\tmp\\swingby_lock.txt","a");
            if (lg)
            {
                fprintf(lg, "UNLOCK_SHADOW_RT src=%p shadow=%p hr=0x%08lx\n",
                        (void *)iface, (void *)s_shadow_lock_surface, (unsigned long)hr);
                fclose(lg);
            }
        }

        IDirect3DSurface9_Release(s_shadow_lock_surface);
        s_shadow_lock_iface = NULL;
        s_shadow_lock_surface = NULL;
        return hr == WINEDDERR_NOTLOCKED ? D3DERR_INVALIDCALL : hr;
    }

    /* Inject snap AFTER game has written its thumbnail data, before unmap.
     * .dat persistence is handled exclusively by the Swift side (patchDatFileThumbnail);
     * this inject is live-preview only. */
    if (iface == s_unlock_iface && s_unlock_data != NULL)
    {
        int injected = swingby_inject_snap_slot(s_unlock_data, s_unlock_pitch, s_unlock_slot);
        if (injected)
        {
            FILE *lg = fopen("Z:\\tmp\\swingby_inject_fired.txt","a");
            if (lg) { fprintf(lg,"slot=%d ok\n", s_unlock_slot); fclose(lg); }
        }
        s_unlock_iface = NULL;
        s_unlock_data  = NULL;
    }

    /* Diag: sample what the application wrote into a full-resolution surface
     * during a write lock, just before it is unmapped. */
    if (iface == s_diag_write_iface && s_diag_write_data)
    {
        struct wined3d_map_desc md;
        unsigned long avg;
        md.data = s_diag_write_data;
        md.row_pitch = s_diag_write_pitch;
        md.slice_pitch = 0;
        avg = swingby_log_lock_sample("DIAG_UNLOCK_WRITE", iface, &s_diag_write_desc, NULL, 0, &md);
        swingby_diag("UNLOCK_WRITE surf=%p avg_after_write=%lu", (void *)iface, avg);
        s_diag_write_iface = NULL;
        s_diag_write_data = NULL;
    }

    wined3d_mutex_lock();
    hr = wined3d_resource_unmap(wined3d_texture_get_resource(surface->wined3d_texture), surface->sub_resource_idx);
    if (SUCCEEDED(hr) && surface->texture)
        d3d9_texture_flag_auto_gen_mipmap(surface->texture);
    wined3d_mutex_unlock();

    if (hr == WINEDDERR_NOTLOCKED)
    {
        D3DRESOURCETYPE type;
        if (surface->texture)
            type = IDirect3DBaseTexture9_GetType(&surface->texture->IDirect3DBaseTexture9_iface);
        else
            type = D3DRTYPE_SURFACE;
        hr = type == D3DRTYPE_TEXTURE ? D3D_OK : D3DERR_INVALIDCALL;
    }
    return hr;
}

static HRESULT WINAPI d3d9_surface_GetDC(IDirect3DSurface9 *iface, HDC *dc)
{
    struct d3d9_surface *surface = impl_from_IDirect3DSurface9(iface);
    struct wined3d_sub_resource_desc _d;
    HRESULT hr;

    TRACE("iface %p, dc %p.\n", iface, dc);

    wined3d_mutex_lock();
    hr = wined3d_texture_get_dc(surface->wined3d_texture, surface->sub_resource_idx, dc);
    wined3d_texture_get_sub_resource_desc(surface->wined3d_texture, surface->sub_resource_idx, &_d);
    wined3d_mutex_unlock();

    swingby_diag("GetDC surf=%p %ux%u hr=0x%08x dc=%p",
            (void *)iface, _d.width, _d.height, (unsigned)hr, dc ? (void *)*dc : NULL);

    return hr;
}

static HRESULT WINAPI d3d9_surface_ReleaseDC(IDirect3DSurface9 *iface, HDC dc)
{
    struct d3d9_surface *surface = impl_from_IDirect3DSurface9(iface);
    struct wined3d_sub_resource_desc _d;
    HRESULT hr;

    TRACE("iface %p, dc %p.\n", iface, dc);

    wined3d_mutex_lock();
    hr = wined3d_texture_release_dc(surface->wined3d_texture, surface->sub_resource_idx, dc);
    wined3d_texture_get_sub_resource_desc(surface->wined3d_texture, surface->sub_resource_idx, &_d);
    if (SUCCEEDED(hr) && surface->texture)
        d3d9_texture_flag_auto_gen_mipmap(surface->texture);
    wined3d_mutex_unlock();

    swingby_diag("ReleaseDC surf=%p %ux%u hr=0x%08x", (void *)iface, _d.width, _d.height, (unsigned)hr);

    return hr;
}

static const struct IDirect3DSurface9Vtbl d3d9_surface_vtbl =
{
    /* IUnknown */
    d3d9_surface_QueryInterface,
    d3d9_surface_AddRef,
    d3d9_surface_Release,
    /* IDirect3DResource9 */
    d3d9_surface_GetDevice,
    d3d9_surface_SetPrivateData,
    d3d9_surface_GetPrivateData,
    d3d9_surface_FreePrivateData,
    d3d9_surface_SetPriority,
    d3d9_surface_GetPriority,
    d3d9_surface_PreLoad,
    d3d9_surface_GetType,
    /* IDirect3DSurface9 */
    d3d9_surface_GetContainer,
    d3d9_surface_GetDesc,
    d3d9_surface_LockRect,
    d3d9_surface_UnlockRect,
    d3d9_surface_GetDC,
    d3d9_surface_ReleaseDC,
};

static void STDMETHODCALLTYPE surface_wined3d_object_destroyed(void *parent)
{
    struct d3d9_surface *surface = parent;
    d3d9_resource_cleanup(&surface->resource);
    free(surface);
}

static const struct wined3d_parent_ops d3d9_surface_wined3d_parent_ops =
{
    surface_wined3d_object_destroyed,
};

struct d3d9_surface *d3d9_surface_create(struct wined3d_texture *wined3d_texture,
        unsigned int sub_resource_idx, IUnknown *container)
{
    IDirect3DBaseTexture9 *texture;
    struct d3d9_surface *surface;

    if (!(surface = calloc(1, sizeof(*surface))))
        return NULL;

    surface->IDirect3DSurface9_iface.lpVtbl = &d3d9_surface_vtbl;
    d3d9_resource_init(&surface->resource);
    surface->resource.refcount = 0;
    list_init(&surface->rtv_entry);
    surface->container = container;
    surface->wined3d_texture = wined3d_texture;
    surface->sub_resource_idx = sub_resource_idx;
    surface->swapchain = wined3d_texture_get_swapchain(wined3d_texture);

    if (surface->container && SUCCEEDED(IUnknown_QueryInterface(surface->container,
            &IID_IDirect3DBaseTexture9, (void **)&texture)))
    {
        surface->texture = unsafe_impl_from_IDirect3DBaseTexture9(texture);
        IDirect3DBaseTexture9_Release(texture);
    }

    wined3d_texture_set_sub_resource_parent(wined3d_texture, sub_resource_idx,
            surface, &d3d9_surface_wined3d_parent_ops);

    TRACE("Created surface %p.\n", surface);
    return surface;
}

static void STDMETHODCALLTYPE view_wined3d_object_destroyed(void *parent)
{
    struct d3d9_surface *surface = parent;

    /* If the surface reference count drops to zero, we release our reference
     * to the view, but don't clear the pointer yet, in case e.g. a
     * GetRenderTarget() call brings the surface back before the view is
     * actually destroyed. When the view is destroyed, we need to clear the
     * pointer, or a subsequent surface AddRef() would reference it again.
     *
     * This is safe because as long as the view still has a reference to the
     * texture, the surface is also still alive, and we're called before the
     * view releases that reference. */
    surface->wined3d_rtv = NULL;
    list_remove(&surface->rtv_entry);
}

static const struct wined3d_parent_ops d3d9_view_wined3d_parent_ops =
{
    view_wined3d_object_destroyed,
};

struct d3d9_device *d3d9_surface_get_device(const struct d3d9_surface *surface)
{
    IDirect3DDevice9Ex *device;
    device = surface->texture ? &surface->texture->parent_device->IDirect3DDevice9Ex_iface : surface->parent_device;
    return impl_from_IDirect3DDevice9Ex(device);
}

struct wined3d_rendertarget_view *d3d9_surface_acquire_rendertarget_view(struct d3d9_surface *surface)
{
    HRESULT hr;

    /* The surface reference count can be equal to 0 when this function is
     * called. In order to properly manage the render target view reference
     * count, we temporarily increment the surface reference count. */
    d3d9_surface_AddRef(&surface->IDirect3DSurface9_iface);

    if (surface->wined3d_rtv)
        return surface->wined3d_rtv;

    if (FAILED(hr = wined3d_rendertarget_view_create_from_sub_resource(surface->wined3d_texture,
            surface->sub_resource_idx, surface, &d3d9_view_wined3d_parent_ops, &surface->wined3d_rtv)))
    {
        ERR("Failed to create rendertarget view, hr %#lx.\n", hr);
        d3d9_surface_Release(&surface->IDirect3DSurface9_iface);
        return NULL;
    }

    if (surface->texture)
        list_add_head(&surface->texture->rtv_list, &surface->rtv_entry);

    return surface->wined3d_rtv;
}

void d3d9_surface_release_rendertarget_view(struct d3d9_surface *surface,
        struct wined3d_rendertarget_view *rtv)
{
    if (rtv)
        d3d9_surface_Release(&surface->IDirect3DSurface9_iface);
}

struct d3d9_surface *unsafe_impl_from_IDirect3DSurface9(IDirect3DSurface9 *iface)
{
    if (!iface)
        return NULL;
    assert(iface->lpVtbl == &d3d9_surface_vtbl);

    return impl_from_IDirect3DSurface9(iface);
}
