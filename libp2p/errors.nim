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
    IndefiniteError,
    OverrunError,
    OverflowError,
    IncompleteError,
    EndOfBufferError,
    NoSupportError,
    IncorrectHexadecimalError,

    VarintError,

    BufferWriteError,
    BufferReadError,

    IncorrectEncodingError,

    ProtobufIncorrectFieldError,
    ProtobufFieldSizeTooLargeError,

    MultiHashIncorrectHashError,
    MultiHashInputSizeError,
    MultiHashIncorrectFormatError,

    CidIncorrectError,
    CidIncorrectContentType,
    CidIncorrectHashType,
    CidIncorrectVersion,

    RandomGeneratorError,

    Ed25519IncorrectBinaryFormError,

    RSAKeyGenerationError,
    RSAKeyComputationError,
    RSAKeyTooSmallError,
    RSAIncorrectBinaryFormError,
    RSASignatureError,

    EcNistIncorrectError,
    EcNistKeyGenerationError,
    EcNistKeyComputationError,
    EcNistIncorrectBinaryFormError,
    EcNistCurveNoSupportError,
    EcNistDifferentCurvesError,
    EcNistMultiplicationError,
    EcNistSignatureError,

    CryptoIncorrectBinaryFormError,
    CryptoSchemeNoSupportError,
    CryptoEcdheIncorrectSchemeError,
    CryptoEcdheUnequalSchemesError,

    MultiAddressMalformedError,
    MultiAddressDecodeError,
    MultiAddressEncodeError,
    MultiAddressProtocolNotFoundError,
    MultiAddressProtocolIncorrectError,
    MultiAddressIncorrectError,
    MultiAddressNoSupportError


  LibResult*[T] = Result[T, Error]
