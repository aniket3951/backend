/**
 * Royal Photowaala - Admin Dashboard JavaScript
 * Handles bookings, gallery, logo, and home images management
 */

// Use relative paths - works with any host/port
const API_BASE = '/api';
const dbName = "RoyalPhotowaalaDB";
let db;

// ==================== INITIALIZATION ====================
document.addEventListener('DOMContentLoaded', async function() {
  initIndexedDB();
  initNavigation();
  initDarkMode();
  loadBookings();
  
  // Handle archive button
  const archiveBtn = document.getElementById('archiveBookings');
  if (archiveBtn) {
    archiveBtn.addEventListener('click', async function(e) {
      e.preventDefault();
      
      if (!confirm('Are you sure you want to archive old bookings? This action cannot be undone.')) {
        return;
      }
      
      try {
        setButtonLoading(this, true);
        const response = await fetch('/api/archive-bookings', { method: 'POST', credentials: 'include' });
        const data = await response.json();
        
        if (response.ok) {
          showToast(`Successfully archived ${data.archived_count || 0} bookings`, 'success');
          loadBookings();
        } else {
          throw new Error(data.error || 'Failed to archive bookings');
        }
      } catch (error) {
        console.error('Archive error:', error);
        showToast(error.message || 'Failed to archive bookings', 'error');
      } finally {
        setButtonLoading(this, false);
      }
    });
  }
  
  // Event Listeners
  document.getElementById('addImageForm').addEventListener('submit', handleAddImage);
  document.getElementById('addLogoForm').addEventListener('submit', handleAddLogo);
  document.getElementById('addHomeForm').addEventListener('submit', handleAddHomeImage);
  document.getElementById('refreshBookings').addEventListener('click', loadBookings);
  document.getElementById('statusFilter').addEventListener('change', filterBookings);
  document.querySelector('.modal-close')?.addEventListener('click', closeModal);
  
  window.refreshBookings = loadBookings;
});

function setButtonLoading(button, isLoading) {
  if (isLoading) {
    button.disabled = true;
    button.dataset.originalText = button.textContent;
    button.textContent = '⏳ Loading...';
  } else {
    button.disabled = false;
    if (button.dataset.originalText) {
      button.textContent = button.dataset.originalText;
    }
  }
}

// ==================== INDEXEDDB SETUP ====================
function initIndexedDB() {
  const request = indexedDB.open(dbName, 1);
  
  request.onerror = () => showToast("Database error occurred", "error");
  
  request.onsuccess = (event) => {
    db = event.target.result;
    renderGalleryImages();
    renderLogo();
    renderHomeImages();
    updateImageStats();
  };
  
  request.onupgradeneeded = (event) => {
    db = event.target.result;
    if (!db.objectStoreNames.contains("galleryImages"))
      db.createObjectStore("galleryImages", { keyPath: "id", autoIncrement: true });
    if (!db.objectStoreNames.contains("homeImages"))
      db.createObjectStore("homeImages", { keyPath: "id", autoIncrement: true });
    if (!db.objectStoreNames.contains("websiteLogo"))
      db.createObjectStore("websiteLogo", { keyPath: "id" });
  };
}

// ==================== NAVIGATION ====================
function initNavigation() {
  const navLinks = document.querySelectorAll('.nav-link');
  const sections = document.querySelectorAll('.content-section');
  
  navLinks.forEach(link => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      const targetSection = link.dataset.section;
      
      // Update active states
      navLinks.forEach(l => l.classList.remove('active'));
      link.classList.add('active');
      
      sections.forEach(s => s.classList.remove('active'));
      document.getElementById(targetSection)?.classList.add('active');
    });
  });
}

// ==================== DARK MODE ====================
function initDarkMode() {
  const darkBtn = document.querySelector('.toggle-mode');
  
  // Load saved theme
  if (localStorage.getItem("theme") === "dark") {
    document.body.classList.add("dark");
    darkBtn.textContent = "🌞 Light Mode";
  }
  
  darkBtn.addEventListener("click", () => {
    document.body.classList.toggle("dark");
    const isDark = document.body.classList.contains("dark");
    darkBtn.textContent = isDark ? "🌞 Light Mode" : "🌙 Dark Mode";
    localStorage.setItem("theme", isDark ? "dark" : "light");
  });
}

// ==================== BOOKINGS MANAGEMENT ====================
async function loadBookings() {
  const tbody = document.getElementById('bookingsTableBody');
  tbody.innerHTML = '<tr><td colspan="8" class="loading-cell">Loading bookings...</td></tr>';
  
  try {
    const response = await fetch(`${API_BASE}/bookings`, {
      credentials: 'include' // Include session cookies
    });
    
    if (!response.ok) {
      if (response.status === 401) {
        window.location.href = '/admin_login';
        return;
      }
      throw new Error('Failed to fetch bookings');
    }
    
    const data = await response.json();
    const bookings = data.bookings || [];
    
    // Update statistics
    updateBookingStats(bookings);
    
    // Render bookings table
    renderBookingsTable(bookings);
    
  } catch (error) {
    console.error('Error loading bookings:', error);
    tbody.innerHTML = '<tr><td colspan="8" class="error-cell">Failed to load bookings. Please refresh.</td></tr>';
    showToast('Failed to load bookings', 'error');
  }
}

function renderBookingsTable(bookings) {
  const tbody = document.getElementById('bookingsTableBody');
  
  if (bookings.length === 0) {
    tbody.innerHTML = '<tr><td colspan="8" class="empty-cell">No bookings found</td></tr>';
    return;
  }
  
  tbody.innerHTML = bookings.map(booking => `
    <tr data-id="${booking.id}">
      <td>${booking.id}</td>
      <td>${escapeHtml(booking.name)}</td>
      <td><a href="mailto:${escapeHtml(booking.email)}">${escapeHtml(booking.email)}</a></td>
      <td><a href="tel:${escapeHtml(booking.phone)}">${escapeHtml(booking.phone)}</a></td>
      <td>${escapeHtml(booking.package)}</td>
      <td>${formatDate(booking.date)}</td>
      <td>
        <select class="status-select" data-id="${booking.id}" onchange="updateBookingStatus(${booking.id}, this.value)">
          <option value="pending" ${booking.status === 'pending' ? 'selected' : ''}>⏳ Pending</option>
          <option value="confirmed" ${booking.status === 'confirmed' ? 'selected' : ''}>✅ Confirmed</option>
          <option value="cancelled" ${booking.status === 'cancelled' ? 'selected' : ''}>❌ Cancelled</option>
          <option value="completed" ${booking.status === 'completed' ? 'selected' : ''}>🎉 Completed</option>
        </select>
      </td>
      <td class="action-buttons">
        <button class="btn-view" onclick="viewBookingDetails(${booking.id})" title="View Details">👁️</button>
        <button class="btn-delete" onclick="deleteBooking(${booking.id})" title="Delete">🗑️</button>
      </td>
    </tr>
  `).join('');
}

async function updateBookingStatus(bookingId, newStatus) {
  try {
    const response = await fetch(`${API_BASE}/bookings/${bookingId}/status`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ status: newStatus })
    });
    
    if (!response.ok) throw new Error('Failed to update status');
    
    showToast(`Booking status updated to ${newStatus}`, 'success');
    loadBookings(); // Refresh to update stats
    
  } catch (error) {
    console.error('Error updating status:', error);
    showToast('Failed to update status', 'error');
    loadBookings(); // Revert UI
  }
}

async function deleteBooking(bookingId) {
  if (!confirm('Are you sure you want to delete this booking?')) return;
  
  try {
    const response = await fetch(`${API_BASE}/bookings/${bookingId}`, {
      method: 'DELETE',
      credentials: 'include'
    });
    
    if (!response.ok) throw new Error('Failed to delete booking');
    
    showToast('Booking deleted successfully', 'success');
    loadBookings();
    
  } catch (error) {
    console.error('Error deleting booking:', error);
    showToast('Failed to delete booking', 'error');
  }
}

function viewBookingDetails(bookingId) {
  // Find booking in current table
  const row = document.querySelector(`tr[data-id="${bookingId}"]`);
  if (!row) return;
  
  const cells = row.querySelectorAll('td');
  const modalBody = document.getElementById('modalBody');
  
  modalBody.innerHTML = `
    <div class="booking-details">
      <p><strong>Booking ID:</strong> ${cells[0].textContent}</p>
      <p><strong>Name:</strong> ${cells[1].textContent}</p>
      <p><strong>Email:</strong> ${cells[2].textContent}</p>
      <p><strong>Phone:</strong> ${cells[3].textContent}</p>
      <p><strong>Package:</strong> ${cells[4].textContent}</p>
      <p><strong>Event Date:</strong> ${cells[5].textContent}</p>
      <p><strong>Status:</strong> ${cells[6].querySelector('select').selectedOptions[0].textContent}</p>
    </div>
  `;
  
  document.getElementById('bookingModal').classList.add('show');
}

function closeModal() {
  document.getElementById('bookingModal').classList.remove('show');
}

function filterBookings() {
  const filterValue = document.getElementById('statusFilter').value;
  const rows = document.querySelectorAll('#bookingsTableBody tr');
  
  rows.forEach(row => {
    if (filterValue === 'all') {
      row.style.display = '';
    } else {
      const select = row.querySelector('.status-select');
      if (select && select.value === filterValue) {
        row.style.display = '';
      } else {
        row.style.display = 'none';
      }
    }
  });
}

function updateBookingStats(bookings) {
  document.getElementById('totalBookings').textContent = bookings.length;
  document.getElementById('pendingBookings').textContent = 
    bookings.filter(b => b.status === 'pending').length;
  document.getElementById('confirmedBookings').textContent = 
    bookings.filter(b => b.status === 'confirmed').length;
}

// ==================== GALLERY MANAGEMENT ====================
function renderGalleryImages() {
  const tx = db.transaction("galleryImages", "readonly");
  const store = tx.objectStore("galleryImages");
  
  store.getAll().onsuccess = (e) => {
    const images = e.target.result || [];
    const container = document.getElementById('galleryImages');
    
    if (images.length === 0) {
      container.innerHTML = '<p class="empty-state">No images yet. Upload your first image!</p>';
      return;
    }
    
    container.innerHTML = images.map(img => `
      <div class="image-item" data-id="${img.id}">
        <div class="drag-handle" title="Drag to reorder">⋮⋮</div>
        <img src="${img.data}" alt="Gallery Image" loading="lazy" />
        <button class="delete-btn" onclick="deleteGalleryImage(${img.id})" title="Delete">🗑️</button>
      </div>
    `).join('');
    
    // Initialize drag and drop
    initSortable(container, 'galleryImages');
    
    updateImageStats();
  };
}

function handleAddImage(e) {
  e.preventDefault();
  const file = e.target.imageFile.files[0];
  
  if (!file) {
    showToast('Please select an image', 'error');
    return;
  }
  
  if (file.size > 100 * 1024 * 1024) {
    showToast('Image must be less than 100MB', 'error');
    return;
  }
  
  const reader = new FileReader();
  reader.onload = () => {
    const tx = db.transaction("galleryImages", "readwrite");
    tx.objectStore("galleryImages").add({ data: reader.result });
    tx.oncomplete = () => {
      renderGalleryImages();
      e.target.reset();
      showToast('Image added to gallery', 'success');
    };
  };
  reader.readAsDataURL(file);
}

function deleteGalleryImage(id) {
  if (!confirm('Delete this image from gallery?')) return;
  
  const tx = db.transaction("galleryImages", "readwrite");
  tx.objectStore("galleryImages").delete(id);
  tx.oncomplete = () => {
    renderGalleryImages();
    showToast('Image deleted', 'success');
  };
}

// ==================== LOGO MANAGEMENT ====================
function renderLogo() {
  const tx = db.transaction("websiteLogo", "readonly");
  const store = tx.objectStore("websiteLogo");
  
  store.get(1).onsuccess = (e) => {
    const logo = e.target.result;
    const logoPreview = document.getElementById('logoPreview');
    const noLogo = document.getElementById('noLogo');
    
    if (logo && logo.data) {
      logoPreview.src = logo.data;
      logoPreview.style.display = 'block';
      noLogo.style.display = 'none';
    } else {
      logoPreview.style.display = 'none';
      noLogo.style.display = 'block';
    }
  };
}

function handleAddLogo(e) {
  e.preventDefault();
  const file = e.target.logoFile.files[0];
  
  if (!file) {
    showToast('Please select a logo', 'error');
    return;
  }
  
  if (file.size > 100 * 1024 * 1024) {
    showToast('Logo must be less than 100MB', 'error');
    return;
  }
  
  const reader = new FileReader();
  reader.onload = () => {
    const tx = db.transaction("websiteLogo", "readwrite");
    tx.objectStore("websiteLogo").put({ id: 1, data: reader.result });
    tx.oncomplete = () => {
      renderLogo();
      e.target.reset();
      showToast('Logo updated successfully', 'success');
    };
  };
  reader.readAsDataURL(file);
}

// ==================== HOME IMAGES MANAGEMENT ====================
function renderHomeImages() {
  const tx = db.transaction("homeImages", "readonly");
  const store = tx.objectStore("homeImages");
  
  store.getAll().onsuccess = (e) => {
    const images = e.target.result || [];
    const container = document.getElementById('homeImages');
    
    if (images.length === 0) {
      container.innerHTML = '<p class="empty-state">No home images yet. Upload your first image!</p>';
      return;
    }
    
    container.innerHTML = images.map(img => `
      <div class="image-item" data-id="${img.id}">
        <div class="drag-handle" title="Drag to reorder">⋮⋮</div>
        <img src="${img.data}" alt="Home Image" loading="lazy" />
        <button class="delete-btn" onclick="deleteHomeImage(${img.id})" title="Delete">🗑️</button>
      </div>
    `).join('');
    
    // Initialize drag and drop
    initSortable(container, 'homeImages');
  };
}

function handleAddHomeImage(e) {
  e.preventDefault();
  const file = e.target.homeFile.files[0];
  
  if (!file) {
    showToast('Please select an image', 'error');
    return;
  }
  
  if (file.size > 100 * 1024 * 1024) {
    showToast('Image must be less than 100MB', 'error');
    return;
  }
  
  const reader = new FileReader();
  reader.onload = () => {
    const tx = db.transaction("homeImages", "readwrite");
    tx.objectStore("homeImages").add({ data: reader.result });
    tx.oncomplete = () => {
      renderHomeImages();
      e.target.reset();
      showToast('Home image added', 'success');
    };
  };
  reader.readAsDataURL(file);
}

function deleteHomeImage(id) {
  if (!confirm('Delete this home image?')) return;
  
  const tx = db.transaction("homeImages", "readwrite");
  tx.objectStore("homeImages").delete(id);
  tx.oncomplete = () => {
    renderHomeImages();
    showToast('Home image deleted', 'success');
  };
}

// ==================== DRAG AND DROP ====================
function initSortable(container, storeName) {
  if (!container || container.children.length === 0) return;
  
  Sortable.create(container, {
    animation: 200,
    handle: '.drag-handle',
    ghostClass: 'sortable-ghost',
    chosenClass: 'sortable-chosen',
    dragClass: 'sortable-drag',
    onEnd: function(evt) {
      saveImageOrder(container, storeName);
      showToast('Image order updated', 'success');
    }
  });
}

function saveImageOrder(container, storeName) {
  const items = Array.from(container.querySelectorAll('.image-item'));
  const orderedIds = items.map(item => parseInt(item.dataset.id));
  
  // Get all images from store
  const tx = db.transaction(storeName, "readwrite");
  const store = tx.objectStore(storeName);
  
  store.getAll().onsuccess = (e) => {
    const allImages = e.target.result || [];
    
    // Clear the store
    const clearTx = db.transaction(storeName, "readwrite");
    const clearStore = clearTx.objectStore(storeName);
    clearStore.clear();
    
    clearTx.oncomplete = () => {
      // Re-add images in new order
      const addTx = db.transaction(storeName, "readwrite");
      const addStore = addTx.objectStore(storeName);
      
      orderedIds.forEach(id => {
        const image = allImages.find(img => img.id === id);
        if (image) {
          // Remove old id to let autoIncrement assign new sequential ids
          const { id: oldId, ...imageData } = image;
          addStore.add(imageData);
        }
      });
      
      addTx.oncomplete = () => {
        // Refresh the display
        if (storeName === 'galleryImages') {
          renderGalleryImages();
        } else if (storeName === 'homeImages') {
          renderHomeImages();
        }
      };
    };
  };
}

// ==================== UTILITY FUNCTIONS ====================
function updateImageStats() {
  const tx = db.transaction("galleryImages", "readonly");
  tx.objectStore("galleryImages").count().onsuccess = (e) => {
    document.getElementById('totalImages').textContent = e.target.result;
  };
}

function showToast(message, type = 'info') {
  const toast = document.getElementById('toast');
  toast.textContent = message;
  toast.className = `toast show ${type}`;
  
  setTimeout(() => {
    toast.classList.remove('show');
  }, 3000);
}

function formatDate(dateString) {
  const date = new Date(dateString);
  return date.toLocaleDateString('en-IN', { 
    year: 'numeric', 
    month: 'short', 
    day: 'numeric' 
  });
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// Close modal when clicking outside
window.addEventListener('click', (e) => {
  const modal = document.getElementById('bookingModal');
  if (e.target === modal) {
    closeModal();
  }
});


