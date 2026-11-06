//! What one inline transaction holds per rail and SPP shape, every axis measured jointly through the real encoder.

use std::fmt::Write;

use anyhow::Result;
use custom_ring_interface::{
    key_catalog::{FrameKey, RingKey, TransferShape, RING_KEYS},
    RingRail,
};
use spr_interface::{shape::SPP_SUPPORTED_SHAPES, MAX_INTERFACE_TRANSFERS};

use super::{FrameRail, Legs, Load, Shape, Transfer, TransferFit, MIN};

/// The least load a salted read carries.
const SALTED: Load = Load {
    name: "salted",
    policy_roots: true,
    curator: false,
    legs: Legs::Sol,
    ..MIN
};

/// One inline transaction at the widest owner run its legs leave.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct Reach {
    pub frame: FrameRail,
    pub inputs: usize,
    pub outputs: usize,
    pub legs: usize,
    /// Distinct live input owners, the run and any owner signing inside SPP's proof.
    pub rows: usize,
    pub salted: bool,
}

impl FrameRail {
    /// Rows past the run, each signs inside SPP's proof.
    const fn unsigned_rows(self) -> usize {
        match self {
            Self::InProof | Self::Hidden | Self::HiddenEntry => 1,
            _ => 0,
        }
    }
}

impl Reach {
    /// A hidden sender's legs name one destination, a delegate reads no salted list.
    pub const fn leg_owners(self) -> usize {
        match (self.frame, self.salted) {
            (_, false) | (FrameRail::Delegate | FrameRail::AnonymousDelegate, _) => 0,
            (FrameRail::Hidden | FrameRail::HiddenEntry, true) => (self.legs > 0) as usize,
            _ => self.legs,
        }
    }

    /// Every distinct row, output owner and withdrawal owner, the salted worst case.
    pub const fn subjects(self) -> usize {
        self.rows + self.outputs + self.leg_owners()
    }

    fn frame_key(self, wide: bool) -> FrameKey {
        FrameKey {
            rail: self.frame.rail(),
            inputs: self.inputs,
            outputs: self.outputs,
            spends_default_ring: self.frame.entry(),
            wide,
        }
    }
}

fn reach(frame: FrameRail, shape: Shape, legs: usize, salted: bool) -> Result<Option<Reach>> {
    let transfer = Transfer {
        frame,
        shape,
        load: if salted { SALTED } else { MIN },
        owners: 0,
        legs,
    };
    let rows = |run: usize| match frame.has_owner_run() {
        true => (run + frame.unsigned_rows()).min(shape.n_inputs()),
        false => shape.n_inputs(),
    };
    Ok(transfer.widest_settled_run()?.map(|(run, _)| Reach {
        frame,
        inputs: shape.n_inputs(),
        outputs: shape.n_outputs(),
        legs,
        rows: rows(run),
        salted,
    }))
}

/// Every inline transaction at each leg count, salted and with no policy.
pub(super) fn reaches() -> Result<Vec<Reach>> {
    let mut reaches = Vec::new();
    for frame in FrameRail::ALL {
        for shape in SPP_SUPPORTED_SHAPES {
            if !frame.rail().supports(shape) {
                continue;
            }
            if let Some(plain) = reach(frame, shape, 0, false)? {
                reaches.push(plain);
            }
            if frame.rail().is_delegate() {
                continue;
            }
            for legs in 0..=MAX_INTERFACE_TRANSFERS {
                match reach(frame, shape, legs, true)? {
                    Some(salted) => reaches.push(salted),
                    None => break,
                }
            }
        }
    }
    Ok(reaches)
}

/// What the inline transactions a key serves reach, each axis on its own and the subjects jointly.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct KeyReach {
    pub inputs: usize,
    pub outputs: usize,
    pub legs: usize,
    pub rows: usize,
    pub subjects: usize,
    pub records: usize,
    /// The spend that opens the most subjects.
    pub widest: Reach,
}

/// A key of fixed width holds a spend within its legs at no more than its rows, the wide key of the
/// same frame takes every other spend.
fn holds(shape: TransferShape, reach: Reach) -> Option<Reach> {
    match fixed_width(shape) {
        false => (reach.frame_key(true).shape() == Some(shape)).then_some(reach),
        true => (reach.frame_key(false).shape() == Some(shape)
            && reach.legs <= usize::from(shape.withdrawals))
        .then_some(Reach {
            rows: reach.rows.min(usize::from(shape.owners)),
            ..reach
        }),
    }
}

/// Narrow and small entry keys keep their widths, a spend past them moves to a wide key.
fn fixed_width(shape: TransferShape) -> bool {
    let wide_entry = FrameKey {
        rail: RingRail::Confidential,
        inputs: 1,
        outputs: 1,
        spends_default_ring: true,
        wide: true,
    }
    .shape();
    !shape.wide || (shape.entry && wide_entry != Some(shape))
}

/// Each key's inline reach, `None` for a key no inline transaction uses.
pub(super) fn key_reaches(reaches: &[Reach]) -> Result<Vec<(RingKey, Option<KeyReach>)>> {
    let mut keyed = Vec::new();
    for key in RING_KEYS {
        let Some(shape) = TransferShape::of(key.circuit) else {
            continue;
        };
        let held: Vec<Reach> = reaches
            .iter()
            .filter_map(|reach| holds(shape, *reach))
            .collect();
        if held.is_empty() {
            keyed.push((key, None));
            continue;
        }
        // A narrow key reads no salted record, so its tracking rows are input owners and outputs alone.
        let subjects = |reach: &Reach| match shape.wide {
            false => reach.rows + reach.outputs,
            true => reach.subjects(),
        };
        let records = |reach: &Reach| match shape.wide {
            false => reach.rows + 2 * reach.outputs + reach.leg_owners() + reach.inputs,
            true => 2 * reach.subjects() + reach.outputs + reach.inputs,
        };
        let most = |value: &dyn Fn(&Reach) -> usize| held.iter().map(value).max().unwrap_or(0);
        keyed.push((
            key,
            Some(KeyReach {
                inputs: most(&|reach| reach.inputs),
                outputs: most(&|reach| reach.outputs),
                legs: most(&|reach| reach.legs),
                rows: most(&|reach| reach.rows),
                subjects: most(&subjects),
                records: most(&records),
                widest: *held
                    .iter()
                    .max_by_key(|reach| subjects(reach))
                    .unwrap_or(&held[0]),
            }),
        ));
    }
    Ok(keyed)
}

pub fn run() -> Result<()> {
    let reaches = reaches()?;
    let mut table = String::new();
    writeln!(
        table,
        "| key | inputs | outputs | legs | rows | subjects | records | widest spend |"
    )?;
    writeln!(table, "|---|---|---|---|---|---|---|---|")?;
    for (key, reach) in key_reaches(&reaches)? {
        match reach {
            Some(reach) => writeln!(
                table,
                "| {} | {} | {} | {} | {} | {} | {} | {} {}x{} legs {} rows {} |",
                key.name,
                reach.inputs,
                reach.outputs,
                reach.legs,
                reach.rows,
                reach.subjects,
                reach.records,
                reach.widest.frame.name(),
                reach.widest.inputs,
                reach.widest.outputs,
                reach.widest.legs,
                reach.widest.rows
            )?,
            None => writeln!(table, "| {} | dropped |", key.name)?,
        }
    }
    writeln!(table)?;
    writeln!(
        table,
        "Each rail and SPP shape at its least spend, no policy, no leg and the rail's least run."
    )?;
    writeln!(
        table,
        "| rail | shape | key | inline bytes | accounts | signatures | frame | SPP CPI | inline |"
    )?;
    writeln!(table, "|---|---|---|---|---|---|---|---|---|")?;
    for frame in FrameRail::ALL {
        for shape in SPP_SUPPORTED_SHAPES
            .into_iter()
            .filter(|shape| frame.rail().supports(*shape))
        {
            let least = Transfer {
                frame,
                shape,
                load: MIN,
                owners: frame.required_owners(),
                legs: 0,
            };
            let key = [false, true]
                .into_iter()
                .find_map(|wide| {
                    FrameKey {
                        rail: frame.rail(),
                        inputs: shape.n_inputs(),
                        outputs: shape.n_outputs(),
                        spends_default_ring: frame.entry(),
                        wide,
                    }
                    .shape()
                })
                .and_then(|shape| {
                    RING_KEYS
                        .iter()
                        .find(|key| TransferShape::of(key.circuit) == Some(shape))
                })
                .map_or("none", |key| key.name);
            match least.measure()? {
                TransferFit::Measured(measured) => writeln!(
                    table,
                    "| {} | {}x{} | {key} | {} | {} | {} | {} | {} | {} |",
                    frame.name(),
                    shape.n_inputs(),
                    shape.n_outputs(),
                    measured.fit.bytes,
                    measured.fit.addresses,
                    measured.fit.signatures,
                    measured.frame_len,
                    measured.spp_cpi_len,
                    measured.fits(),
                )?,
                TransferFit::Unkeyed => writeln!(
                    table,
                    "| {} | {}x{} | {key} | - | - | - | - | - | unkeyed |",
                    frame.name(),
                    shape.n_inputs(),
                    shape.n_outputs(),
                )?,
            }
        }
    }
    writeln!(table)?;
    writeln!(table, "| rail | shape | salted | legs | rows | subjects |")?;
    writeln!(table, "|---|---|---|---|---|---|")?;
    for reach in &reaches {
        writeln!(
            table,
            "| {} | {}x{} | {} | {} | {} | {} |",
            reach.frame.name(),
            reach.inputs,
            reach.outputs,
            reach.salted,
            reach.legs,
            reach.rows,
            reach.subjects()
        )?;
    }
    print!("{table}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_standard_key_holds_its_inline_reach() {
        let reaches = reaches().unwrap();
        for (key, reach) in key_reaches(&reaches).unwrap() {
            let shape = TransferShape::of(key.circuit).unwrap();
            let reach =
                reach.unwrap_or_else(|| panic!("{} serves no inline transaction", key.name));
            assert_eq!(
                (reach.inputs, reach.outputs, reach.legs, reach.rows),
                (
                    usize::from(shape.inputs),
                    usize::from(shape.outputs),
                    usize::from(shape.withdrawals),
                    usize::from(shape.owners)
                ),
                "{} widths",
                key.name
            );
            assert_eq!(
                reach.subjects,
                usize::from(shape.tracking),
                "{} tracking",
                key.name
            );
            assert!(
                reach.records <= usize::from(shape.records) + usize::from(shape.inputs),
                "{} records {} exceed capacity {}",
                key.name,
                reach.records,
                usize::from(shape.records) + usize::from(shape.inputs)
            );
        }
    }
}
