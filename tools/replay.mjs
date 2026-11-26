import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {isDeepStrictEqual} from 'node:util';

const boundFields = [
  'service', 'audience', 'credentialID', 'authorizationRef', 'inputKind',
  'hashes', 'hashAlgorithmOID', 'signAlgo', 'signAlgoParams',
  'operationMode', 'policyEpoch'
];

const copy = value => structuredClone(value);
const sameScope = (left, right) => left.service === right.service &&
  left.audience === right.audience;
const statusOf = record => record.status === 'completed'
  ? `completed:${record.result}` : record.status;
const validDigest = value => typeof value === 'string' &&
  Buffer.from(value, 'base64').length === 32 &&
  Buffer.from(value, 'base64').toString('base64') === value;
const sameBoundFields = (left, right) => boundFields.every(
  field => field === 'hashes'
    ? Array.isArray(left.hashes) && Array.isArray(right.hashes) &&
      left.hashes.length === right.hashes.length &&
      left.hashes.every((value, i) => validDigest(value) && validDigest(right.hashes[i]) &&
        Buffer.from(value, 'base64').equals(Buffer.from(right.hashes[i], 'base64')))
    : isDeepStrictEqual(left[field], right[field])
);

function validClientId(value) {
  if (typeof value !== 'string' || !/^sc1:[A-Za-z0-9_-]{22}$/.test(value)) return false;
  const encoded = value.slice(4);
  const bytes = Buffer.from(encoded, 'base64url');
  return bytes.length === 16 && bytes.toString('base64url') === encoded;
}

function runCase(corpus, vector) {
  const request = copy(corpus.baseRequest);
  const authorization = copy(corpus.baseAuthorization);
  const baseCaller = copy(corpus.baseAuthenticatedCaller);
  let resolvedSelection = {...copy(corpus.baseSelection), ...copy(vector.selectionPatch ?? {})};
  const capability = {...corpus.baseCapability, ...vector.capabilityPatch};
  let durable = {record: null, grantUse: [], revoked: false};
  let now = 1;
  let invocations = 0;

  function callerFor(step) {
    return {...baseCaller, ...copy(step.callerPatch ?? {})};
  }

  function submit(candidate, caller) {
    if (caller.authenticated !== true) return 'access-denied';
    if (capability.profile !== 'sc1' ||
        capability.evidence !== 'authenticated-service-policy' ||
        capability.boundary !== 'service' ||
        capability.durableReservation !== true ||
        capability.clientLookup !== true) return 'unsupported';
    if (candidate.inputKind !== 'digest' || candidate.operationMode !== 'A' ||
        !Array.isArray(candidate.hashes) || candidate.hashes.length !== 1 ||
        !validDigest(candidate.hashes[0]) || !validClientId(candidate.clientData)) return 'unsupported';
    if (!sameScope(candidate, caller)) return 'unauthorized';
    const prior = durable.record;
    if (prior && sameScope(prior.caller, caller) &&
        prior.request.clientData === candidate.clientData) {
      return sameBoundFields(prior.request, candidate) ? statusOf(prior) : 'collision';
    }
    if (durable.revoked || now > authorization.expiresAt) return 'unauthorized';
    if (!sameBoundFields(candidate, authorization) ||
        !isDeepStrictEqual(resolvedSelection, corpus.baseAuthorizationSelection)) return 'unauthorized';
    if (durable.grantUse.some(use => sameScope(use.caller, caller) &&
        use.authorizationRef === candidate.authorizationRef)) return 'grant-spent';
    if (prior) return 'capacity-unavailable';
    durable.grantUse.push({caller: copy(caller), authorizationRef: candidate.authorizationRef});
    durable.record = {request: copy(candidate), caller: copy(caller),
      selection: copy(resolvedSelection),
      status: 'reserved', result: null};
    return 'reserved';
  }

  function stepResult(step) {
    const record = durable.record;
    switch (step.action) {
      case 'submit': return submit({...request, ...copy(step.requestPatch ?? {})}, callerFor(step));
      case 'dispatch':
        if (!record || record.status !== 'reserved') return 'invalid-transition';
        if (durable.revoked) return (record.status = 'authorization-revoked');
        if (now > authorization.expiresAt) return (record.status = 'authorization-expired');
        {
          const effective = {...record.request, ...copy(step.effectiveRequestPatch ?? {})};
          const selected = {...resolvedSelection, ...copy(step.effectiveSelectionPatch ?? {})};
          if (effective.clientData !== record.request.clientData ||
              !sameBoundFields(effective, record.request) ||
              !isDeepStrictEqual(selected, record.selection)) return (record.status = 'boundary-mismatch');
        }
        record.status = 'unresolved';
        invocations++;
        return 'unresolved';
      case 'complete':
        if (!record) return 'invalid-transition';
        if (record.status !== 'unresolved' && record.status !== 'completed') return 'invalid-transition';
        if (step.authenticated !== true) return 'unauthenticated-result';
        if (step.resultBindingPatch) {
          const claimed = {...record.request, ...copy(step.resultBindingPatch)};
          if (claimed.clientData !== record.request.clientData ||
              !sameBoundFields(claimed, record.request)) return 'outcome-mismatch';
        }
        if (step.resultSelectionPatch && !isDeepStrictEqual(
          {...record.selection, ...copy(step.resultSelectionPatch)}, record.selection)) return 'outcome-mismatch';
        if (record.status === 'completed') return record.result === step.result
          ? statusOf(record) : 'immutable-result';
        record.result = step.result;
        record.status = 'completed';
        return 'completed';
      case 'lookup': {
        const caller = callerFor(step);
        if (caller.authenticated !== true) return 'access-denied';
        if (!record) return 'unknown';
        if (!sameScope(caller, record.caller)) return 'unknown';
        if ((step.clientData ?? request.clientData) !== record.request.clientData) return 'unknown';
        return statusOf(record);
      }
      case 'remap':
        resolvedSelection = {...resolvedSelection, ...copy(step.selectionPatch)};
        return 'selection-changed';
      case 'cancel': {
        const caller = callerFor(step);
        if (caller.authenticated !== true) return 'access-denied';
        if (!record || !sameScope(caller, record.caller)) return 'unknown';
        return statusOf(record);
      }
      case 'restart':
        durable = copy(durable);
        return durable.record ? statusOf(durable.record) : 'unknown';
      case 'revoke': durable.revoked = true; return 'revoked';
      case 'advance': now = step.now; return 'time-advanced';
      default: throw new Error(`Unknown action ${step.action}`);
    }
  }

  for (const [index, step] of vector.steps.entries()) {
    assert.equal(stepResult(step), step.expect, `${vector.id} step ${index + 1}`);
  }
  assert.equal(invocations, vector.invocations, `${vector.id} invocation count`);
}

export function replayCases(corpus) {
  assert.equal(corpus.format, 'synthetic-protected-signing-v1');
  assert.equal(new Set(corpus.cases.map(x => x.id)).size, corpus.cases.length);
  assert.match(corpus.sourceMessageHex, /^(?:[a-f0-9]{2})+$/);
  const digest = createHash('sha256').update(Buffer.from(corpus.sourceMessageHex, 'hex')).digest('base64');
  assert.deepEqual(corpus.baseRequest.hashes, [digest], 'source message digest');
  assert.equal(corpus.baseRequest.clientData, 'sc1:AAECAwQFBgcICQoLDA0ODw');
  for (const vector of corpus.cases) runCase(corpus, vector);
  return corpus.cases.length;
}
