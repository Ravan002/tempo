//! Messages exchanged on the top-of-block channel.

use alloy_primitives::B256;
use bytes::{Buf, BufMut, Bytes};
use commonware_codec::{EncodeSize, Error, RangeCfg, Read, ReadExt as _, Write};

/// Maximum number of transactions in one [`Submit`].
pub const MAX_TXS_PER_SUBMIT: usize = 1024;
/// Maximum size of one encoded transaction in a [`Submit`].
pub const MAX_TX_BYTES: usize = 128 * 1024;
/// Maximum number of transaction hashes in one [`Built`].
const MAX_BUILT_HASHES: usize = 64 * 1024;

/// A message on the top-of-block channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    /// Leader to operators: the sender opened its lane for a round it proposes.
    Leader(Leader),
    /// Operator to leader: signed transactions for the lane of a round.
    Submit(Submit),
    /// Leader to operator: what the lane did with a [`Submit`].
    Ack(Ack),
    /// Leader to operators: the proposal built from a round's lane.
    Built(Built),
}

/// Announces that the sender leads round `(epoch, view)` and opened its lane.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Leader {
    pub epoch: u64,
    pub view: u64,
    /// Height of the block being built.
    pub height: u64,
    /// Hash of the parent block.
    pub parent: B256,
    /// Time after which the builder takes the lane.
    pub window_ms: u64,
}

/// Signed transactions for the lane of round `(epoch, view)`.
///
/// Each transaction replaces the previous transaction of its signer in the
/// round.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Submit {
    pub epoch: u64,
    pub view: u64,
    /// Operator-chosen sequence number echoed in the [`Ack`].
    pub seq: u64,
    /// EIP-2718 encoded transactions.
    pub txs: Vec<Bytes>,
}

/// The outcome of a [`Submit`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum AckStatus {
    /// The lane processed the submission; see the counters.
    Ok = 0,
    /// The receiver does not lead this round.
    NotOpen = 1,
    /// The receiver's builder already took the lane for this round.
    Closed = 2,
    /// The sender is not a registered operator, or its access expired.
    Unauthorized = 3,
}

/// What the leader's lane did with a [`Submit`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ack {
    pub epoch: u64,
    pub view: u64,
    pub seq: u64,
    pub status: AckStatus,
    pub accepted: u32,
    pub replaced: u32,
    /// Transactions dropped because they did not decode or recover, exceeded
    /// the operator's limits, or belong to a maker held by another operator.
    pub rejected: u32,
    /// Time between opening the lane and receiving the submission.
    pub since_open_us: u64,
}

/// The proposal built for round `(epoch, view)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Built {
    pub epoch: u64,
    pub view: u64,
    pub height: u64,
    pub block_hash: B256,
    pub tx_count: u32,
    /// Hashes of the lane transactions that made it into the block, in block
    /// order. They are the first transactions of the block.
    pub top_of_block: Vec<B256>,
}

fn write_b256(value: &B256, buf: &mut impl BufMut) {
    value.0.write(buf);
}

fn read_b256(buf: &mut impl Buf) -> Result<B256, Error> {
    <[u8; 32]>::read(buf).map(B256::from)
}

impl Write for Message {
    fn write(&self, buf: &mut impl BufMut) {
        match self {
            Self::Leader(Leader {
                epoch,
                view,
                height,
                parent,
                window_ms,
            }) => {
                0u8.write(buf);
                epoch.write(buf);
                view.write(buf);
                height.write(buf);
                write_b256(parent, buf);
                window_ms.write(buf);
            }
            Self::Submit(Submit {
                epoch,
                view,
                seq,
                txs,
            }) => {
                1u8.write(buf);
                epoch.write(buf);
                view.write(buf);
                seq.write(buf);
                txs.write(buf);
            }
            Self::Ack(Ack {
                epoch,
                view,
                seq,
                status,
                accepted,
                replaced,
                rejected,
                since_open_us,
            }) => {
                2u8.write(buf);
                epoch.write(buf);
                view.write(buf);
                seq.write(buf);
                (*status as u8).write(buf);
                accepted.write(buf);
                replaced.write(buf);
                rejected.write(buf);
                since_open_us.write(buf);
            }
            Self::Built(Built {
                epoch,
                view,
                height,
                block_hash,
                tx_count,
                top_of_block,
            }) => {
                3u8.write(buf);
                epoch.write(buf);
                view.write(buf);
                height.write(buf);
                write_b256(block_hash, buf);
                tx_count.write(buf);
                top_of_block.len().write(buf);
                for hash in top_of_block {
                    write_b256(hash, buf);
                }
            }
        }
    }
}

impl EncodeSize for Message {
    fn encode_size(&self) -> usize {
        1 + match self {
            Self::Leader(_) => 8 * 4 + 32,
            Self::Submit(submit) => 8 * 3 + submit.txs.encode_size(),
            Self::Ack(_) => 8 * 4 + 1 + 4 * 3,
            Self::Built(built) => {
                8 * 3
                    + 32
                    + 4
                    + built.top_of_block.len().encode_size()
                    + 32 * built.top_of_block.len()
            }
        }
    }
}

impl Read for Message {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, Error> {
        match u8::read(buf)? {
            0 => Ok(Self::Leader(Leader {
                epoch: u64::read(buf)?,
                view: u64::read(buf)?,
                height: u64::read(buf)?,
                parent: read_b256(buf)?,
                window_ms: u64::read(buf)?,
            })),
            1 => Ok(Self::Submit(Submit {
                epoch: u64::read(buf)?,
                view: u64::read(buf)?,
                seq: u64::read(buf)?,
                txs: Vec::<Bytes>::read_cfg(
                    buf,
                    &(
                        RangeCfg::from(..=MAX_TXS_PER_SUBMIT),
                        RangeCfg::from(..=MAX_TX_BYTES),
                    ),
                )?,
            })),
            2 => Ok(Self::Ack(Ack {
                epoch: u64::read(buf)?,
                view: u64::read(buf)?,
                seq: u64::read(buf)?,
                status: match u8::read(buf)? {
                    0 => AckStatus::Ok,
                    1 => AckStatus::NotOpen,
                    2 => AckStatus::Closed,
                    3 => AckStatus::Unauthorized,
                    other => return Err(Error::InvalidEnum(other)),
                },
                accepted: u32::read(buf)?,
                replaced: u32::read(buf)?,
                rejected: u32::read(buf)?,
                since_open_us: u64::read(buf)?,
            })),
            3 => {
                let epoch = u64::read(buf)?;
                let view = u64::read(buf)?;
                let height = u64::read(buf)?;
                let block_hash = read_b256(buf)?;
                let tx_count = u32::read(buf)?;
                let len = usize::read_cfg(buf, &RangeCfg::from(..=MAX_BUILT_HASHES))?;
                let top_of_block = (0..len).map(|_| read_b256(buf)).collect::<Result<_, _>>()?;
                Ok(Self::Built(Built {
                    epoch,
                    view,
                    height,
                    block_hash,
                    tx_count,
                    top_of_block,
                }))
            }
            other => Err(Error::InvalidEnum(other)),
        }
    }
}

#[cfg(test)]
mod tests {
    use commonware_codec::Encode as _;

    use super::*;

    #[test]
    fn messages_round_trip() {
        let messages = [
            Message::Leader(Leader {
                epoch: 1,
                view: 2,
                height: 3,
                parent: B256::repeat_byte(4),
                window_ms: 5,
            }),
            Message::Submit(Submit {
                epoch: 1,
                view: 2,
                seq: 3,
                txs: vec![Bytes::from_static(b"a"), Bytes::from_static(b"bc")],
            }),
            Message::Ack(Ack {
                epoch: 1,
                view: 2,
                seq: 3,
                status: AckStatus::Closed,
                accepted: 4,
                replaced: 5,
                rejected: 6,
                since_open_us: 7,
            }),
            Message::Built(Built {
                epoch: 1,
                view: 2,
                height: 3,
                block_hash: B256::repeat_byte(4),
                tx_count: 5,
                top_of_block: vec![B256::repeat_byte(6), B256::repeat_byte(7)],
            }),
        ];
        for message in messages {
            let encoded = message.encode();
            assert_eq!(encoded.len(), message.encode_size());
            assert_eq!(Message::read(&mut encoded.as_ref()).unwrap(), message);
        }
    }
}
