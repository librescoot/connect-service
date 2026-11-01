const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

const script = fs.readFileSync(path.join(__dirname, 'pair.js'), 'utf8');
function load(hash) {
  const inputs = { code: { value: '' }, qr: { value: '' } };
  const message = { hidden: true };
  const replacements = [];
  vm.runInNewContext(script, {
    location: { hash },
    history: { replaceState: (...args) => replacements.push(args) },
    document: {
      querySelector: selector => inputs[selector === '[name="code"]' ? 'code' : 'qr'],
      getElementById: () => message,
    },
  });
  return { inputs, message, replacements };
}

test('valid short-code fragment is stripped and prefilled without submitting', () => {
  const result = load('#code=01234-ABCDE');
  assert.equal(result.inputs.code.value, '01234-ABCDE');
  assert.equal(result.inputs.qr.value, '');
  assert.equal(result.message.hidden, false);
  assert.equal(result.replacements[0][2], '/pair');
});

test('existing token fragment remains supported', () => {
  const token = 'a'.repeat(43);
  const result = load('#' + token);
  assert.equal(result.inputs.qr.value, token);
  assert.equal(result.inputs.code.value, '');
  assert.equal(result.message.hidden, false);
  assert.equal(result.replacements[0][2], '/pair');
});

test('invalid short-code fragments do not prefill', () => {
  for (const hash of ['#code=01234-ABCIO', '#code=01234-abcde', '#code=01234-ABCDE&x=1', '#code=01234ABCDE', '#code=%30%31%32%33%34-ABCDE', '#code=01234-ABCDE\n']) {
    const result = load(hash);
    assert.equal(result.inputs.code.value, '', hash);
    assert.equal(result.inputs.qr.value, '', hash);
    assert.equal(result.message.hidden, true, hash);
    assert.equal(result.replacements[0][2], '/pair');
  }
});
