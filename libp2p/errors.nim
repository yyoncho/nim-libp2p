## Nim-Libp2p
## Copyright (c) 2018 Status Research & Development GmbH
## Licensed under either of
##  * Apache License, version 2.0, ([LICENSE-APACHE](LICENSE-APACHE))
##  * MIT license ([LICENSE-MIT](LICENSE-MIT))
## at your option.
## This file may not be copied, modified, or distributed except according to
## those terms.
import result
export result

type
  Error* = enum
    NoError,
    GenericError,
    IncorrectError,
    OverrunError,
    OverflowError,
    IncompleteError,
    EndOfBufferError,
    NoSupportError,

    VarintError,
    IncorrectEncodingError,

    MultiAddressMalformedError,
    MultiAddressDecodeError,
    MultiAddressEncodeError,
    MultiAddressProtocolNotFoundError,
    MultiAddressProtocolIncorrectError,
    MultiAddressIncorrectError,
    MultiAddressNoSupportError,

