const value = location.hash.slice(1);
if (location.hash) history.replaceState(null, "", "/pair");
if (value.length === 16 && /^code=[0-9ABCDEFGHJKMNPQRSTVWXYZ]{5}-[0-9ABCDEFGHJKMNPQRSTVWXYZ]{5}$/.test(value)) {
  const input = document.querySelector('[name="code"]');
  if (input) {
    input.value = value.slice(5);
    document.getElementById("qr-detected").hidden = false;
  }
} else if (/^[A-Za-z0-9_-]{43}$/.test(value)) {
  const input = document.querySelector('[name="qr"]');
  if (input) {
    input.value = value;
    document.getElementById("qr-detected").hidden = false;
  }
}
