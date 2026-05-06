const form = document.getElementById('upload-form');
const fileInput = document.getElementById('zip-file');
const resultBox = document.getElementById('result');

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const file = fileInput.files[0];
  if (!file) return;

  const fd = new FormData();
  fd.append('file', file);

  resultBox.textContent = '분석 중...';
  try {
    const res = await fetch('/api/upload', { method: 'POST', body: fd });
    const body = await res.json();
    resultBox.textContent = JSON.stringify(body, null, 2);
  } catch (err) {
    resultBox.textContent = `오류: ${err.message}`;
  }
});
