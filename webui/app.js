const cam = document.querySelector('.cam');
const feed = document.querySelector('.cam-feed');
const shutter = document.getElementById('shutter');
const sheet = document.getElementById('sheet');
const scrim = document.getElementById('scrim');
const flip = document.querySelector('.flip');

let facing = 'environment';
let stream;

async function startCamera() {
  if (!navigator.mediaDevices?.getUserMedia) return;
  try {
    if (stream) stream.getTracks().forEach(t => t.stop());
    stream = await navigator.mediaDevices.getUserMedia({
      video: { facingMode: { ideal: facing } },
      audio: false,
    });
    feed.srcObject = stream;
  } catch {
    // no permission / no camera — the dark fallback background stays
  }
}

flip.addEventListener('click', () => {
  facing = facing === 'environment' ? 'user' : 'environment';
  startCamera();
});

function openSheet() {
  scrim.hidden = false;
  sheet.setAttribute('aria-hidden', 'false');
  requestAnimationFrame(() => sheet.classList.add('open'));
}

function closeSheet() {
  sheet.classList.remove('open');
  sheet.setAttribute('aria-hidden', 'true');
  sheet.addEventListener('transitionend', () => { scrim.hidden = true; }, { once: true });
}

shutter.addEventListener('click', () => {
  if (cam.classList.contains('busy')) return;
  cam.classList.add('busy');
  // brief tightened sweep to read as "analysing", then surface the match
  setTimeout(() => {
    cam.classList.remove('busy');
    openSheet();
  }, 1400);
});

scrim.addEventListener('click', closeSheet);

startCamera();
