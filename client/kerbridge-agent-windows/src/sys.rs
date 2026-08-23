//! Thin Win32 helpers shared by the windows: wide strings, geometry, DPI scaling,
//! word-wrap measurement, rasterizing the SVG logo into a tray HICON, and the
//! process plumbing (single instance, restart registration, shell open).
//! Everything here is toolkit-agnostic -- it knows nothing of our controls, our
//! roles or our windows.

use std::ffi::c_void;

use kerbridge_client::describe::Condition;
use kerbridge_client::icon::{
    BADGE, BANG_DOT, BANG_STEM, Badge, DISC, GLYPH_MIN, KNOCKOUT, WARN_VERTICES, mark,
};
use resvg::tiny_skia::{
    BlendMode, ColorU8, FillRule, LineCap, LineJoin, Paint, Path, PathBuilder, Pixmap, Stroke,
    Transform,
};
use windows_sys::Win32::Foundation::{ERROR_ALREADY_EXISTS, GetLastError, HWND, RECT};
use windows_sys::Win32::Graphics::Gdi::{
    BI_RGB, BITMAPINFO, BITMAPINFOHEADER, CreateBitmap, CreateDIBSection, DIB_RGB_COLORS,
    DT_CALCRECT, DT_SINGLELINE, DT_WORDBREAK, DeleteObject, DrawTextW, GetDC, HDC, HFONT,
    ReleaseDC, SelectObject,
};
use windows_sys::Win32::System::Recovery::RegisterApplicationRestart;
use windows_sys::Win32::System::Threading::CreateMutexW;
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    CreateIconIndirect, HICON, ICONINFO, SPI_GETWORKAREA, SystemParametersInfoW,
};
use windows_sys::Win32::UI::WindowsAndMessaging::{FindWindowW, SW_SHOWNORMAL};

/// UTF-16, NUL-terminated -- for the many Win32 `*W` calls. Keep the returned Vec
/// alive for as long as the pointer is in use.
pub fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Logical (96-DPI) pixels → physical, for the given window DPI.
pub fn dip(v: i32, dpi: u32) -> i32 {
    v * dpi as i32 / 96
}

/// Work area of the primary monitor (excludes the taskbar), physical pixels.
pub fn work_area() -> Option<(i32, i32, i32, i32)> {
    let mut r = RECT { left: 0, top: 0, right: 0, bottom: 0 };
    let ok =
        unsafe { SystemParametersInfoW(SPI_GETWORKAREA, 0, &mut r as *mut _ as *mut c_void, 0) };
    (ok != 0).then_some((r.left, r.top, r.right, r.bottom))
}

/// Top-left that anchors a w×h popup to the work-area corner nearest the tray. The
/// taskbar edge is inferred from how the work area is inset. `margin` is physical px.
pub fn anchor_pos(w: i32, h: i32, margin: i32) -> (i32, i32) {
    let Some((wl, wt, wr, wb)) = work_area() else {
        return (120, 120);
    };
    let (x, y) = if wt > 0 {
        (wr - w - margin, wt + margin) // taskbar top -> top-right
    } else if wl > 0 {
        (wl + margin, wb - h - margin) // taskbar left -> bottom-left
    } else {
        (wr - w - margin, wb - h - margin) // taskbar bottom/right/hidden -> bottom-right
    };
    (x.max(0), y.max(0))
}

/// Center a w×h window on the work area.
pub fn center_on_work_area(w: i32, h: i32) -> (i32, i32) {
    if let Some((wl, wt, wr, wb)) = work_area() {
        ((wl + ((wr - wl) - w) / 2).max(0), (wt + ((wb - wt) - h) / 2).max(0))
    } else {
        (120, 120)
    }
}

/// Word-wrapped height (physical px) of `text` drawn in `font` within `width` px.
/// Used to size multi-line STATIC labels so nothing clips.
pub fn measure_text(font: HFONT, text: &str, width: i32) -> i32 {
    unsafe {
        let hdc: HDC = GetDC(std::ptr::null_mut());
        let old = SelectObject(hdc, font as _);
        let mut r = RECT { left: 0, top: 0, right: width, bottom: 0 };
        let w = wide(text);
        DrawTextW(hdc, w.as_ptr(), -1, &mut r, DT_CALCRECT | DT_WORDBREAK);
        SelectObject(hdc, old);
        ReleaseDC(std::ptr::null_mut(), hdc);
        r.bottom - r.top
    }
}

/// The rendered width of a single line in `font`, physical px. The stacking rule
/// needs the label's own width, not the width of the column it would wrap in.
pub fn measure_width(font: HFONT, text: &str) -> i32 {
    unsafe {
        let hdc: HDC = GetDC(std::ptr::null_mut());
        let old = SelectObject(hdc, font as _);
        let mut r = RECT { left: 0, top: 0, right: 0, bottom: 0 };
        let w = wide(text);
        DrawTextW(hdc, w.as_ptr(), -1, &mut r, DT_CALCRECT | DT_SINGLELINE);
        SelectObject(hdc, old);
        ReleaseDC(std::ptr::null_mut(), hdc);
        r.right - r.left
    }
}

/// Rasterize an SVG into a square HICON with alpha, for the tray. The SVG is the
/// single source of truth for the logo; we render it at the requested size.
pub fn svg_to_hicon(svg: &str, size: u32) -> HICON {
    pixmap_to_hicon(&render_logo(svg, size), size)
}

/// The logo as a notification-area icon: the taskbar's own ink, with the
/// condition carried by the two axes `kerbridge_client::icon` decides.
///
/// **The badge is the one thing on this icon that is colored**, which is the one
/// thing the two platforms differ in. That reverses an older absolute of ours, on
/// a measurement: monochrome cannot separate `Working` from `Flaky` at 16 px,
/// because a full-ink badge on a full-ink mark has no contrast left to spend.
/// Shape carries it for a viewer who cannot tell amber from red.
///
/// `warn` and `danger` are `theme.rs`'s own, keyed on the **taskbar's** theme
/// rather than the app's, because that is the surface this is drawn on.
pub fn status_icon(svg: &str, size: u32, on_dark: bool, condition: Condition) -> HICON {
    let m = mark(condition);
    let mut pixmap = render_logo(svg, size);
    flatten(&mut pixmap, if on_dark { 0xff } else { 0x00 }, m.fade);
    let (warn, danger) = crate::theme::badge_colors(on_dark);
    if let Some(kind) = m.badge {
        let color = match kind {
            Badge::Warn => warn,
            Badge::Stop => danger,
        };
        badge(&mut pixmap, size, color, kind);
    }
    pixmap_to_hicon(&pixmap, size)
}

/// Draw the overlay in the bottom-right corner, over a transparent ring that
/// separates it from a mark of its own ink.
fn badge(pixmap: &mut Pixmap, size: u32, color: u32, kind: Badge) {
    let size = size as f32;
    let r = size * DISC;
    let (cx, cy) = (size - size * BADGE / 2.0, size - size * BADGE / 2.0);

    let mut paint = Paint::default();
    // theme.rs holds COLORREF -- 0x00bbggrr, which is the byte order Win32 wants
    // and the reverse of what a paint does.
    let (b, g, r8) = ((color >> 16) as u8, (color >> 8) as u8, color as u8);
    paint.set_color_rgba8(r8, g, b, 0xff);
    paint.anti_alias = true;

    let shape = match kind {
        Badge::Stop => PathBuilder::from_circle(cx, cy, r),
        Badge::Warn => triangle(cx, cy, r),
    };
    let Some(shape) = shape else { return };
    knockout(pixmap, &shape, r);
    pixmap.fill_path(&shape, &paint, FillRule::Winding, Transform::identity(), None);

    if size as u32 >= GLYPH_MIN {
        glyph(pixmap, cx, cy, r, kind);
    }
}

/// The warning triangle at [`WARN_VERTICES`], placed on the badge.
fn triangle(cx: f32, cy: f32, r: f32) -> Option<Path> {
    let mut path = PathBuilder::new();
    for (i, (dx, dy)) in WARN_VERTICES.iter().enumerate() {
        let (x, y) = (cx + r * dx, cy + r * dy);
        if i == 0 {
            path.move_to(x, y);
        } else {
            path.line_to(x, y);
        }
    }
    path.close();
    path.finish()
}

/// The bang or the cross, in the taskbar's ink, inside the badge. Only above
/// [`GLYPH_MIN`]; below it this is a dark smear that makes the badge dirtier
/// rather than more specific.
fn glyph(pixmap: &mut Pixmap, cx: f32, cy: f32, r: f32, kind: Badge) {
    let mut paint = Paint::default();
    // Always dark: both badge colors are light enough to carry black, on either
    // taskbar, and a glyph that followed the taskbar would vanish on one of them.
    paint.set_color_rgba8(0x1a, 0x1a, 0x1a, 0xff);
    paint.anti_alias = true;
    let stroke = Stroke { width: r * 0.22, line_cap: LineCap::Round, ..Stroke::default() };

    let mut path = PathBuilder::new();
    match kind {
        Badge::Warn => {
            let (top, bottom) = BANG_STEM;
            path.move_to(cx, cy + r * top);
            path.line_to(cx, cy + r * bottom);
            path.move_to(cx, cy + r * BANG_DOT);
            path.line_to(cx, cy + r * BANG_DOT + 0.01);
        }
        Badge::Stop => {
            let a = r * 0.42;
            path.move_to(cx - a, cy - a);
            path.line_to(cx + a, cy + a);
            path.move_to(cx + a, cy - a);
            path.line_to(cx - a, cy + a);
        }
    }
    let Some(path) = path.finish() else { return };
    pixmap.stroke_path(&path, &paint, &stroke, Transform::identity(), None);
}

/// Clear a ring in the badge's own outline, so the shape has an edge of its own
/// even where the mark behind it is the same ink.
///
/// Along the silhouette, not a disc around it: the triangle reaches its box's
/// corners, and a disc that fits the box cannot cover them. Round joins, or the
/// apex throws a spike the length of the icon.
fn knockout(pixmap: &mut Pixmap, shape: &Path, r: f32) {
    let paint = Paint { blend_mode: BlendMode::Clear, anti_alias: true, ..Paint::default() };
    let ring = Stroke {
        width: 2.0 * r * (KNOCKOUT - 1.0),
        line_join: LineJoin::Round,
        ..Stroke::default()
    };
    pixmap.stroke_path(shape, &paint, &ring, Transform::identity(), None);
}

fn render_logo(svg: &str, size: u32) -> Pixmap {
    let tree =
        resvg::usvg::Tree::from_str(svg, &resvg::usvg::Options::default()).expect("parse logo svg");
    let mut pixmap = Pixmap::new(size, size).expect("alloc pixmap");
    let scale = size as f32 / tree.size().width();
    resvg::render(&tree, Transform::from_scale(scale, scale), &mut pixmap.as_mut());
    pixmap
}

/// Replace every color with `ink`, keeping the alpha (scaled by `fade`). The
/// antialiased edge survives, because it lives in the alpha channel.
fn flatten(pixmap: &mut Pixmap, ink: u8, fade: f32) {
    for px in pixmap.pixels_mut() {
        let alpha = px.demultiply().alpha();
        if alpha == 0 {
            continue;
        }
        let alpha = (alpha as f32 * fade).round().clamp(0.0, 255.0) as u8;
        *px = ColorU8::from_rgba(ink, ink, ink, alpha).premultiply();
    }
}

/// tiny-skia premultiplied RGBA pixmap -> Win32 HICON (top-down 32bpp straight-alpha
/// BGRA color bitmap + empty mask).
fn pixmap_to_hicon(pixmap: &Pixmap, size: u32) -> HICON {
    let n = (size * size) as usize;
    let mut bgra = vec![0u8; n * 4];
    for (i, px) in pixmap.pixels().iter().enumerate() {
        let c = px.demultiply();
        bgra[i * 4] = c.blue();
        bgra[i * 4 + 1] = c.green();
        bgra[i * 4 + 2] = c.red();
        bgra[i * 4 + 3] = c.alpha();
    }

    unsafe {
        let bmi = BITMAPINFO {
            bmiHeader: BITMAPINFOHEADER {
                biSize: size_of::<BITMAPINFOHEADER>() as u32,
                biWidth: size as i32,
                biHeight: -(size as i32), // top-down
                biPlanes: 1,
                biBitCount: 32,
                biCompression: BI_RGB,
                biSizeImage: 0,
                biXPelsPerMeter: 0,
                biYPelsPerMeter: 0,
                biClrUsed: 0,
                biClrImportant: 0,
            },
            bmiColors: [std::mem::zeroed(); 1],
        };
        let hdc = GetDC(std::ptr::null_mut());
        let mut bits: *mut c_void = std::ptr::null_mut();
        let hbm_color =
            CreateDIBSection(hdc, &bmi, DIB_RGB_COLORS, &mut bits, std::ptr::null_mut(), 0);
        ReleaseDC(std::ptr::null_mut(), hdc);
        if !bits.is_null() {
            std::ptr::copy_nonoverlapping(bgra.as_ptr(), bits as *mut u8, bgra.len());
        }
        // Empty mask: alpha in the color bitmap does the compositing.
        let hbm_mask = CreateBitmap(size as i32, size as i32, 1, 1, std::ptr::null());
        let ii =
            ICONINFO { fIcon: 1, xHotspot: 0, yHotspot: 0, hbmMask: hbm_mask, hbmColor: hbm_color };
        let hicon = CreateIconIndirect(&ii);
        DeleteObject(hbm_color as _);
        DeleteObject(hbm_mask as _);
        hicon
    }
}

/// Low word of a packed WPARAM/LPARAM (e.g. tray callbacks pack the event there).
/// Accepts either by taking the raw machine word.
pub fn loword(v: usize) -> u32 {
    (v as u32) & 0xffff
}

/// High word of a packed WPARAM/LPARAM (e.g. a `WM_COMMAND`'s notification code).
pub fn hiword(v: usize) -> u16 {
    ((v >> 16) & 0xffff) as u16
}

/// Claim the single-instance mutex. False means another agent already owns it.
///
/// `Local\` scope, not `Global\`: the agent is per-user and per-session, because
/// injection has to happen in the interactive user's own logon session. Two users
/// on one machine each get their own tray, which is correct.
///
/// The handle is deliberately never closed -- it is released when the process
/// exits, which is exactly the lifetime the claim should have.
pub fn claim_single_instance(name: &str) -> bool {
    unsafe {
        let h = CreateMutexW(std::ptr::null(), 1, wide(name).as_ptr());
        h.is_null() || GetLastError() != ERROR_ALREADY_EXISTS
    }
}

/// Ask Restart Manager to start this agent again after it shuts us down.
///
/// The MSI's upgrade path replaces a running exe, and Restart Manager is what
/// closes us so the file is free (see `installer/ui/`, dialog `MsiRMFilesInUse`).
/// Detection needs nothing from us -- RM finds the open handle to our own image --
/// but it only *restarts* processes that registered, so without this an upgrade
/// leaves the machine with no tray until the next logon.
///
/// No command line: RM relaunches the registered image with the arguments given
/// here, and every argument this binary takes is an elevated one-shot rather than
/// the tray (see `main`). A failure is not worth reporting -- it costs the restart,
/// not the upgrade.
pub fn register_for_restart() {
    unsafe { RegisterApplicationRestart(std::ptr::null(), 0) };
}

/// Find a top-level window of ours by class name (used to hand off to the
/// already-running instance).
pub fn find_window(class: &str) -> HWND {
    unsafe { FindWindowW(wide(class).as_ptr(), std::ptr::null()) }
}

/// Hand a path to the shell -- opens the log in the user's text editor, or the
/// config folder in Explorer.
pub fn shell_open(path: &str) {
    unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            wide("open").as_ptr(),
            wide(path).as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
}

/// Client width/height of a window, physical px.
pub fn client_size(hwnd: HWND) -> (i32, i32) {
    use windows_sys::Win32::UI::WindowsAndMessaging::GetClientRect;
    let mut r = RECT { left: 0, top: 0, right: 0, bottom: 0 };
    unsafe { GetClientRect(hwnd, &mut r) };
    (r.right - r.left, r.bottom - r.top)
}
