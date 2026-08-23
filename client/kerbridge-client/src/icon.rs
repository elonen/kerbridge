//! What the state icon is made of: the mapping, the geometry, the halo and the
//! glyph threshold.
//!
//! Both agents draw the same mark with their own ink -- Windows flattens it to
//! the taskbar's color and paints the badge, macOS keeps a template image the
//! menu bar colors for itself -- and `client/DESIGN.md` @ the icon says the two
//! platforms differ in exactly that one thing. Everything they are supposed to
//! agree about is here, so "exactly one thing" stays checkable rather than
//! remembered.
//!
//! Nothing renders here: this crate has no rasterizer and does not want one.

use crate::describe::Condition;

/// How much of the logo a condition that is not holding a usable ticket keeps.
pub const FADE: f32 = 0.4;
/// How big the badge is, as a fraction of the icon.
pub const BADGE: f32 = 0.52;
/// The badge's radius, as a fraction of the icon. The triangle is inscribed in
/// the same disc, so the two shapes occupy one box.
pub const DISC: f32 = 0.26;
/// A transparent ring this much bigger than the badge, so it separates from a
/// mark drawn in its own ink. Applied along the badge's own silhouette, not as a
/// disc around it -- a disc leaves the triangle's lower corners touching the mark.
pub const KNOCKOUT: f32 = 1.2;
/// The warning triangle, as offsets from the badge's center in units of its
/// radius. Apex up, base on the floor of the same box the disc fills, so the two
/// badges are the same height and sit on the same line.
///
/// Isosceles rather than equilateral: the badge box's right edge *is* the icon's
/// right edge, so a shape wider than the box is a shape clipped by the frame. An
/// equilateral triangle this tall would be 2.31 boxes wide.
pub const WARN_VERTICES: [(f32, f32); 3] = [(0.0, -1.0), (-1.0, 1.0), (1.0, 1.0)];
/// The bang inside it: the stem's two ends, then the dot, on the same scale.
/// Placed against the triangle above rather than centered in the box -- the shape
/// narrows towards the apex, and the room is low.
pub const BANG_STEM: (f32, f32) = (-0.45, 0.20);
pub const BANG_DOT: f32 = 0.60;
/// Below this the glyph inside the badge is a smear rather than a mark, so the
/// shape goes bare. Measured at 8-9x magnification on both taskbar inks: legible
/// at 24 and 32, dirt at 16 and 20. Nobody sees two sizes side by side, so
/// changing character across the threshold costs nothing. The macOS menu bar
/// draws at 36 device px and is never below it.
pub const GLYPH_MIN: u32 = 24;

/// Which silhouette the badge is. Two shapes, so color is the fast channel and
/// not the only one -- a triangle and a disc stay distinguishable at 8 px, and
/// on macOS shape is all there is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Badge {
    Warn,
    Stop,
}

/// The icon for a condition, on two independent axes.
///
/// **Weight is "nothing to see here"**: full strength means working with nothing
/// wrong, and every other condition is faded -- `WillStop` included, although its
/// share still opens this minute. A full-strength badge over a full-strength mark
/// leaves no contrast to spend, which Windows solves with color and the menu bar
/// has no color to solve with. Fading the mark is what the badge stands on.
///
/// **The badge is the fault**, at the two strengths the failure taxonomy already
/// distinguishes. It stays full strength in every state, so the eye lands on the
/// thing that is wrong rather than on the logo it is drawn over.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Mark {
    /// What to multiply the logo's alpha by.
    pub fade: f32,
    pub badge: Option<Badge>,
}

pub fn mark(condition: Condition) -> Mark {
    let (fade, badge) = match condition {
        Condition::Working => (1.0, None),
        Condition::Flaky | Condition::WillStop => (FADE, Some(Badge::Warn)),
        Condition::Stopped => (FADE, Some(Badge::Stop)),
        Condition::NotStarted => (FADE, None),
    };
    Mark { fade, badge }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One condition is drawn at full strength and it is the one with nothing to
    /// say. Everything else fades, so whatever badge is on it has the contrast to
    /// be read.
    #[test]
    fn only_working_is_full_strength() {
        assert_eq!(mark(Condition::Working), Mark { fade: 1.0, badge: None });
        for c in [Condition::Flaky, Condition::WillStop, Condition::Stopped, Condition::NotStarted]
        {
            assert_eq!(mark(c).fade, FADE, "{c:?}");
        }
        assert_eq!(mark(Condition::Flaky).badge, Some(Badge::Warn));
        assert_eq!(mark(Condition::WillStop).badge, Some(Badge::Warn));
        assert_eq!(mark(Condition::Stopped).badge, Some(Badge::Stop));
        // Never worked here, and nothing is wrong with that.
        assert_eq!(mark(Condition::NotStarted).badge, None);
    }

    /// The triangle sits in the box the disc fills, which is what puts the two
    /// badges on one baseline. Inscribed in the disc instead, it floats half a
    /// radius above the floor.
    #[test]
    fn both_badges_fill_one_box() {
        let ys = WARN_VERTICES.map(|(_, y)| y);
        assert_eq!(ys.iter().cloned().fold(f32::MIN, f32::max), 1.0);
        assert_eq!(ys.iter().cloned().fold(f32::MAX, f32::min), -1.0);
        // And no wider than it is tall, or the icon's own edge clips it.
        for (x, _) in WARN_VERTICES {
            assert!(x.abs() <= 1.0);
        }
    }
}
