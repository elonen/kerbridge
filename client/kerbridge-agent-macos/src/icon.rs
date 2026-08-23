//! The menu-bar image, rasterized from the one logo the whole product uses.
//!
//! `assets/app-icon.svg` is the single source; the Windows agent turns it into a
//! `.ico` at packaging time and this turns it into an `NSImage` at startup. A
//! committed `.icns` would be a second copy to keep in step.
//!
//! **Every state is monochrome** for MacOS.
//!
//! Image stays a **template**: AppKit reads the alpha channel and draws the rest.
//! This ensures correct ink color over any wallpaper, inverts while menu is open,
//! and preserves vibrancy and Reduce Transparency. The Appearance setting changes
//! app widgets but not the menu bar (observed 2026-08-06). The badge glyph is a
//! *hole*, not dark ink—templates have no second color. Only contrast must survive.

use std::cell::RefCell;
use std::sync::OnceLock;

use objc2::AnyThread;
use objc2::rc::Retained;
use objc2_app_kit::{NSBitmapImageRep, NSDeviceRGBColorSpace, NSImage};
use objc2_foundation::NSSize;
use resvg::tiny_skia::{
    BlendMode, ColorU8, FillRule, LineCap, LineJoin, Paint, Path, PathBuilder, Pixmap, Stroke,
    Transform,
};

use kerbridge_client::describe::Condition;
use kerbridge_client::icon::{
    BADGE, BANG_DOT, BANG_STEM, Badge, DISC, GLYPH_MIN, KNOCKOUT, WARN_VERTICES, mark,
};

/// Points, which is what a menu bar wants; the bitmap is rendered at [`SCALE`]
/// times this for Retina and the image is told its logical size.
const SIZE: f64 = 18.0;
const SCALE: u32 = 2;

/// The bitmap's edge in pixels. 36 on every Mac shipped in a decade, which is
/// what puts this permanently above [`GLYPH_MIN`].
const PX: u32 = SIZE as u32 * SCALE;

/// The bare logo.
fn logo() -> &'static Pixmap {
    static LOGO: OnceLock<Pixmap> = OnceLock::new();
    LOGO.get_or_init(|| {
        use resvg::usvg;
        const SVG: &str = include_str!("../../assets/app-icon.svg");
        let tree = usvg::Tree::from_str(SVG, &usvg::Options::default())
            .expect("the committed app-icon.svg parses");
        let mut pixmap = Pixmap::new(PX, PX).expect("a pixmap of a size we chose");
        let size = tree.size();
        let scale = PX as f32 / size.width().max(size.height());
        resvg::render(&tree, Transform::from_scale(scale, scale), &mut pixmap.as_mut());
        pixmap
    })
}

thread_local! {
    /// One composed image per condition.
    static CACHE: RefCell<Vec<(Condition, Retained<NSImage>)>> = const { RefCell::new(Vec::new()) };
}

/// The menu-bar image for a condition.
pub fn state_image(condition: Condition) -> Retained<NSImage> {
    if let Some(image) = CACHE.with(|c| {
        c.borrow().iter().find(|&&(cond, _)| cond == condition).map(|(_, img)| img.clone())
    }) {
        return image;
    }
    let image = compose(condition);
    CACHE.with(|c| c.borrow_mut().push((condition, image.clone())));
    image
}

/// Plain logo at full strength, for the moment before the first status is read.
pub fn template() -> Retained<NSImage> {
    state_image(Condition::Working)
}

fn compose(condition: Condition) -> Retained<NSImage> {
    let m = mark(condition);
    let mut pixmap = Pixmap::new(PX, PX).expect("a pixmap of a size we chose");
    pixmap.data_mut().copy_from_slice(logo().data());
    // Black, because a template keeps the alpha and discards the rest -- so the
    // fade has to live in the alpha channel or it does not exist.
    flatten(&mut pixmap, m.fade);
    if let Some(kind) = m.badge {
        badge(&mut pixmap, kind);
    }
    image_from(&pixmap)
}

/// Scale the alpha and flatten every color to black, keeping the antialiased
/// edge -- which lives in the alpha channel and therefore survives.
fn flatten(pixmap: &mut Pixmap, fade: f32) {
    for px in pixmap.pixels_mut() {
        let alpha = px.demultiply().alpha();
        if alpha == 0 {
            continue;
        }
        let alpha = (alpha as f32 * fade).round().clamp(0.0, 255.0) as u8;
        *px = ColorU8::from_rgba(0, 0, 0, alpha).premultiply();
    }
}

/// The badge in the bottom-right corner: a transparent halo, the shape at full
/// strength over it, and the glyph cleared back out of the shape.
fn badge(pixmap: &mut Pixmap, kind: Badge) {
    let size = PX as f32;
    let r = size * DISC;
    let (cx, cy) = (size - size * BADGE / 2.0, size - size * BADGE / 2.0);

    let mut paint = Paint::default();
    paint.set_color_rgba8(0, 0, 0, 0xff);
    paint.anti_alias = true;
    let shape = match kind {
        Badge::Stop => PathBuilder::from_circle(cx, cy, r),
        Badge::Warn => triangle(cx, cy, r),
    };
    let Some(shape) = shape else { return };
    knockout(pixmap, &shape, r);
    pixmap.fill_path(&shape, &paint, FillRule::Winding, Transform::identity(), None);

    if PX >= GLYPH_MIN {
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

/// The bang or the cross, cleared out of the badge. A template image has one
/// ink, so the glyph is drawn by taking alpha away rather than by adding a
/// second color -- the menu bar's own background then shows through it.
fn glyph(pixmap: &mut Pixmap, cx: f32, cy: f32, r: f32, kind: Badge) {
    let paint = Paint { blend_mode: BlendMode::Clear, anti_alias: true, ..Paint::default() };
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

/// A premultiplied RGBA pixmap as a template `NSImage` whose logical size is
/// [`SIZE`] and whose bitmap is [`SCALE`] times that.
fn image_from(pixmap: &Pixmap) -> Retained<NSImage> {
    let image = NSImage::initWithSize(NSImage::alloc(), NSSize::new(SIZE, SIZE));
    // SAFETY: null planes ask AppKit to allocate and own the buffer, which is
    // then filled below at exactly the size and stride it was given. Handing it
    // our own pointer would mean keeping a Vec alive for precisely as long as the
    // representation, with nothing tying the two lifetimes together.
    unsafe {
        let rep = NSBitmapImageRep::initWithBitmapDataPlanes_pixelsWide_pixelsHigh_bitsPerSample_samplesPerPixel_hasAlpha_isPlanar_colorSpaceName_bytesPerRow_bitsPerPixel(
            NSBitmapImageRep::alloc(),
            std::ptr::null_mut(),
            PX as isize,
            PX as isize,
            8,
            4,
            true,
            false,
            NSDeviceRGBColorSpace,
            (PX * 4) as isize,
            32,
        )
        .expect("a bitmap of a size we chose");

        let dst = rep.bitmapData();
        let src = pixmap.data();
        if !dst.is_null() {
            std::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len());
        }
        image.addRepresentation(&rep);
    }
    image.setTemplate(true);
    image
}
