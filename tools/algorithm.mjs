// A bounded, fail-closed algorithm check for the synthetic CSC profile.
// Key and certificate compatibility remains an authoritative service decision.
const digestLengths = new Map([
  ['2.16.840.1.101.3.4.2.1', 32], // SHA-256
  ['2.16.840.1.101.3.4.2.2', 48], // SHA-384
  ['2.16.840.1.101.3.4.2.3', 64]  // SHA-512
]);
const hashOidByDer = new Map([
  ['608648016503040201', '2.16.840.1.101.3.4.2.1'],
  ['608648016503040202', '2.16.840.1.101.3.4.2.2'],
  ['608648016503040203', '2.16.840.1.101.3.4.2.3']
]);
const mgf1OidDer = '2a864886f70d010108';
const rsaEncryptionOid = '1.2.840.113549.1.1.1';
const pssOid = '1.2.840.113549.1.1.10';

export function canonicalBytes(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 8192) return null;
  const bytes = Buffer.from(value, 'base64');
  return bytes.toString('base64') === value ? bytes : null;
}

function tlv(bytes, offset, limit) {
  if (offset + 2 > limit) throw new Error('truncated DER');
  const tag = bytes[offset];
  let length = bytes[offset + 1];
  let start = offset + 2;
  if (length & 0x80) {
    const count = length & 0x7f;
    if (count === 0 || count > 2 || start + count > limit || bytes[start] === 0)
      throw new Error('invalid DER length');
    length = 0;
    for (let i = 0; i < count; i++) length = length * 256 + bytes[start + i];
    if (length < 128 || (count === 2 && length < 256))
      throw new Error('nonminimal DER length');
    start += count;
  }
  const end = start + length;
  if (end > limit) throw new Error('truncated DER value');
  return {tag, start, end, next: end};
}

function only(bytes, offset, limit, tag) {
  const item = tlv(bytes, offset, limit);
  if (item.tag !== tag || item.next !== limit) throw new Error('unexpected DER item');
  return item;
}

function hashAlgorithm(bytes, offset, limit) {
  const sequence = only(bytes, offset, limit, 0x30);
  const oid = tlv(bytes, sequence.start, sequence.end);
  if (oid.tag !== 0x06) throw new Error('missing hash OID');
  const value = hashOidByDer.get(bytes.subarray(oid.start, oid.end).toString('hex'));
  if (!value) throw new Error('unsupported hash OID');
  if (oid.next < sequence.end) {
    const parameters = only(bytes, oid.next, sequence.end, 0x05);
    if (parameters.start !== parameters.end) throw new Error('invalid hash parameters');
  }
  return value;
}

function maskAlgorithm(bytes, offset, limit) {
  const sequence = only(bytes, offset, limit, 0x30);
  const oid = tlv(bytes, sequence.start, sequence.end);
  if (oid.tag !== 0x06 ||
      bytes.subarray(oid.start, oid.end).toString('hex') !== mgf1OidDer)
    throw new Error('unsupported mask algorithm');
  if (oid.next === sequence.end) throw new Error('missing MGF1 hash');
  return hashAlgorithm(bytes, oid.next, sequence.end);
}

function integer(bytes, offset, limit) {
  const item = only(bytes, offset, limit, 0x02);
  const value = bytes.subarray(item.start, item.end);
  if (value.length === 0 || (value[0] & 0x80) ||
      (value.length > 1 && value[0] === 0 && !(value[1] & 0x80)))
    throw new Error('invalid DER integer');
  let number = 0;
  for (const byte of value) {
    number = number * 256 + byte;
    if (!Number.isSafeInteger(number)) throw new Error('oversized DER integer');
  }
  return number;
}

function pssParams(encoded) {
  const bytes = canonicalBytes(encoded);
  if (!bytes || bytes.length > 4096) throw new Error('invalid PSS parameters');
  const sequence = only(bytes, 0, bytes.length, 0x30);
  let offset = sequence.start;
  let previousTag = 0x9f;
  let hashOid = null;
  let maskHashOid = null;
  let saltLength = 20;
  while (offset < sequence.end) {
    const field = tlv(bytes, offset, sequence.end);
    if (field.tag < 0xa0 || field.tag > 0xa3 || field.tag <= previousTag)
      throw new Error('unexpected PSS field');
    if (field.tag === 0xa0) hashOid = hashAlgorithm(bytes, field.start, field.end);
    if (field.tag === 0xa1) maskHashOid = maskAlgorithm(bytes, field.start, field.end);
    if (field.tag === 0xa2) {
      saltLength = integer(bytes, field.start, field.end);
      if (saltLength === 20) throw new Error('explicit DER default salt length');
    }
    if (field.tag === 0xa3) throw new Error('explicit DER default trailer');
    previousTag = field.tag;
    offset = field.next;
  }
  // Missing hash or MGF fields default to SHA-1 in RFC 8017, below this profile's scope.
  if (!hashOid || !maskHashOid) throw new Error('SHA-1 PSS defaults unsupported');
  return {hashOid, maskHashOid, saltLength};
}

function pssFitsModulus(params, modulusBits) {
  if (!Number.isSafeInteger(modulusBits) || modulusBits < 2) return false;
  const hashLength = digestLengths.get(params.hashOid);
  if (!hashLength) return false;
  // RFC 8017: emLen = ceil((modBits - 1) / 8), and emLen >= hLen + sLen + 2.
  const encodedLength = (BigInt(modulusBits) + 6n) / 8n;
  return encodedLength >= BigInt(hashLength) + BigInt(params.saltLength) + 2n;
}

export function supportedSigningTuple(candidate) {
  if (!Array.isArray(candidate.hashes) || candidate.hashes.length !== 1) return false;
  const digest = canonicalBytes(candidate.hashes[0]);
  if (!digest) return false;
  let hashOid;
  if (candidate.signAlgo === rsaEncryptionOid &&
      candidate.signAlgoParams == null) {
    hashOid = candidate.hashAlgorithmOID;
  } else if (candidate.signAlgo === pssOid) {
    try {
      hashOid = pssParams(candidate.signAlgoParams).hashOid;
    } catch {
      return false;
    }
    if (Object.hasOwn(candidate, 'hashAlgorithmOID') && candidate.hashAlgorithmOID !== hashOid)
      return false;
  } else {
    return false;
  }
  return digestLengths.get(hashOid) === digest.length;
}

// This reads trusted fixture metadata for the actually selected key, not CSC request fields.
// A real service must verify the certificate and enforce restrictions at its signer boundary.
export function selectedKeyEvidencePermits(candidate, evidence, selection) {
  if (evidence?.verified !== true ||
      evidence.credentialID !== candidate.credentialID ||
      evidence.providerIdentity !== selection.providerIdentity ||
      evidence.keyIdentity !== selection.keyIdentity ||
      !Array.isArray(evidence.keyAlgos) ||
      !Object.hasOwn(evidence, 'certifiedSpkiParamsBase64')) return false;

  const keyAlgos = evidence.keyAlgos;
  const spkiAlgorithm = evidence.certifiedSpkiAlgorithm;
  const spkiParams = evidence.certifiedSpkiParamsBase64;
  if (candidate.signAlgo === rsaEncryptionOid) {
    return keyAlgos.includes(rsaEncryptionOid) &&
      spkiAlgorithm === rsaEncryptionOid && spkiParams === 'BQA=';
  }
  if (candidate.signAlgo !== pssOid ||
      !(keyAlgos.includes(rsaEncryptionOid) || keyAlgos.includes(pssOid))) return false;
  if (!Number.isSafeInteger(evidence.keyLenBits) || evidence.keyLenBits < 2) return false;
  let requested;
  try {
    requested = pssParams(candidate.signAlgoParams);
  } catch {
    return false;
  }
  if (!pssFitsModulus(requested, evidence.keyLenBits)) return false;
  if (spkiAlgorithm === rsaEncryptionOid) return spkiParams === 'BQA=';
  if (spkiAlgorithm !== pssOid) return false;
  if (spkiParams === null) return true; // The certified PSS AlgorithmIdentifier omitted parameters.
  try {
    const restricted = pssParams(spkiParams);
    return requested.hashOid === restricted.hashOid &&
      requested.maskHashOid === restricted.maskHashOid &&
      requested.saltLength >= restricted.saltLength;
  } catch {
    return false;
  }
}
