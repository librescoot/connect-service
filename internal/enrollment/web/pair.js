const value = location.hash.slice(1);
if (location.hash) history.replaceState(null, "", "/pair");
if (/^[A-Za-z0-9_-]{43}$/.test(value)) {
  const input = document.querySelector('[name="qr"]');
  if (input) {
    input.value = value;
    document.getElementById("qr-detected").hidden = false;
  }
}
