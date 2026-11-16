const viewer = document.querySelector('.photo-viewer');
const gallery = document.querySelector('[data-gallery]');

if (viewer && gallery && typeof viewer.showModal === 'function') {
  const photos = Array.from(gallery.querySelectorAll('[data-photo]'));
  const image = viewer.querySelector('.viewer-image');
  const original = viewer.querySelector('.viewer-original');
  const position = viewer.querySelector('.viewer-position');
  const stage = viewer.querySelector('.viewer-stage');
  const loading = viewer.querySelector('.viewer-loading');
  const error = viewer.querySelector('.viewer-error');
  let current = 0;
  let opener;

  function show(index) {
    current = (index + photos.length) % photos.length;
    const photo = photos[current];
    original.href = photo.href;
    position.textContent = `${current + 1} of ${photos.length}`;
    loading.hidden = false;
    error.hidden = true;
    image.hidden = true;
    stage.setAttribute('aria-busy', 'true');
    image.alt = photo.dataset.alt;
    image.width = Number(photo.dataset.width);
    image.height = Number(photo.dataset.height);
    image.src = photo.href;
  }

  image.addEventListener('load', () => {
    image.hidden = false;
    loading.hidden = true;
    stage.setAttribute('aria-busy', 'false');
  });

  image.addEventListener('error', () => {
    image.hidden = true;
    loading.hidden = true;
    error.hidden = false;
    stage.setAttribute('aria-busy', 'false');
  });

  gallery.addEventListener('click', (event) => {
    const photo = event.target.closest('[data-photo]');
    if (!photo || event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    event.preventDefault();
    opener = photo;
    show(photos.indexOf(photo));
    viewer.showModal();
    viewer.querySelector('.viewer-close').focus();
  });

  viewer.querySelector('.viewer-close').addEventListener('click', () => viewer.close());
  viewer.querySelector('.viewer-previous').addEventListener('click', () => show(current - 1));
  viewer.querySelector('.viewer-next').addEventListener('click', () => show(current + 1));
  viewer.addEventListener('click', (event) => {
    if (event.target === viewer) viewer.close();
  });
  viewer.addEventListener('keydown', (event) => {
    if (event.altKey || event.ctrlKey || event.metaKey || event.shiftKey) return;
    if (event.key === 'ArrowLeft' || event.key === 'ArrowRight') {
      event.preventDefault();
      show(current + (event.key === 'ArrowRight' ? 1 : -1));
    }
  });
  viewer.addEventListener('close', () => {
    opener?.focus({ preventScroll: true });
  });
}
