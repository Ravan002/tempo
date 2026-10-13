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
    /// Operator to leader: signed transactions for the lane of a round.
    Submit(Submit),
    /// Leader to operator: what the lane did with a [`Submit`].
    Ack(Ack),
    /// Leader to operators: the proposal built from a round's lane.
    Built(Built),
}

/// Signed transactions for the lane of round `(epoch, view)`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Submit {
    pub epoch: u64,
    pub view: u64,
    /// Operator-chosen identifier echoed in the [`Ack`].
    pub id: u64,
    pub txs: Vec<SubmitTx>,
}

/// One transaction in a [`Submit`].
///
/// It replaces the transaction in its slot (signer and nonce key) only if
/// `seq` is higher than the slot's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubmitTx {
    /// EIP-2718 encoded transaction.
    pub tx: Bytes,
    /// Replacement sequence within the transaction's slot.
    pub seq: u64,
    /// Unix time in milliseconds at which the transaction expires; zero never
    /// expires. The leader drops it unless the block's timestamp is earlier.
    pub expires_at_ms: u64,
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
    /// The [`Submit::id`] this acknowledges.
    pub id: u64,
    pub status: AckStatus,
    pub accepted: u32,
    pub replaced: u32,
    /// Transactions dropped because they did not decode or recover, exceeded
    /// the operator's limits, belong to a slot held by another operator, or
    /// did not raise their slot's sequence.
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
            Self::Submit(Submit {
                epoch,
                view,
                id,
                txs,
            }) => {
                0u8.write(buf);
                epoch.write(buf);
                view.write(buf);
                id.write(buf);
                txs.len().write(buf);
                for SubmitTx {
                    tx,
                    seq,
                    expires_at_ms,
                } in txs
                {
                    tx.write(buf);
                    seq.write(buf);
                    expires_at_ms.write(buf);
                }
            }
            Self::Ack(Ack {
                epoch,
                view,
                id,
                status,
                accepted,
                replaced,
                rejected,
                since_open_us,
            }) => {
                1u8.write(buf);
                epoch.write(buf);
                view.write(buf);
                id.write(buf);
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
                2u8.write(buf);
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
            Self::Submit(submit) => {
                8 * 3
                    + submit.txs.len().encode_size()
                    + submit
                        .txs
                        .iter()
                        .map(|tx| tx.tx.encode_size() + 8 * 2)
                        .sum::<usize>()
            }
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
            0 => {
                let epoch = u64::read(buf)?;
                let view = u64::read(buf)?;
                let id = u64::read(buf)?;
                let len = usize::read_cfg(buf, &RangeCfg::from(..=MAX_TXS_PER_SUBMIT))?;
                let txs = (0..len)
                    .map(|_| {
                        Ok(SubmitTx {
                            tx: Bytes::read_cfg(buf, &RangeCfg::from(..=MAX_TX_BYTES))?,
                            seq: u64::read(buf)?,
                            expires_at_ms: u64::read(buf)?,
                        })
                    })
                    .collect::<Result<_, Error>>()?;
                Ok(Self::Submit(Submit {
                    epoch,
                    view,
                    id,
                    txs,
                }))
            }
            1 => Ok(Self::Ack(Ack {
                epoch: u64::read(buf)?,
                view: u64::read(buf)?,
                id: u64::read(buf)?,
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
            2 => {
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
            Message::Submit(Submit {
                epoch: 1,
                view: 2,
                id: 3,
                txs: vec![
                    SubmitTx {
                        tx: Bytes::from_static(b"a"),
                        seq: 4,
                        expires_at_ms: 0,
                    },
                    SubmitTx {
                        tx: Bytes::from_static(b"bc"),
                        seq: 5,
                        expires_at_ms: 6,
                    },
                ],
            }),
            Message::Ack(Ack {
                epoch: 1,
                view: 2,
                id: 3,
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
