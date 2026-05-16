// Modern notification system
function showNotification(message, type = 'success') {
  const notification = document.createElement('div');
  notification.className = `notification notification-${type}`;
  notification.textContent = message;
  notification.style.cssText = `
    position: fixed;
    top: 20px;
    right: 20px;
    padding: 1rem 1.5rem;
    border-radius: 0.75rem;
    box-shadow: 0 10px 15px -3px rgb(0 0 0 / 0.1);
    z-index: 1000;
    animation: slideInRight 0.3s ease;
    font-weight: 500;
    max-width: 300px;
  `;
  
  if (type === 'success') {
    notification.style.background = '#d1fae5';
    notification.style.color = '#065f46';
    notification.style.borderLeft = '4px solid #10b981';
  } else {
    notification.style.background = '#fee2e2';
    notification.style.color = '#991b1b';
    notification.style.borderLeft = '4px solid #ef4444';
  }
  
  document.body.appendChild(notification);
  
  setTimeout(() => {
    notification.style.animation = 'slideOutRight 0.3s ease';
    setTimeout(() => notification.remove(), 300);
  }, 3000);
}

async function purchase(product_id) {
  const button = event.target;
  const originalText = button.textContent;
  
  // Disable button and show loading state
  button.disabled = true;
  button.textContent = 'Processing...';
  button.style.opacity = '0.6';
  button.style.cursor = 'not-allowed';
  
  try {
    const resp = await fetch('/api/purchase', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({product_id: product_id}),
      credentials: 'same-origin'
    });
    
    const data = await resp.json();
    
    if (resp.ok) {
      showNotification(`✅ Successfully purchased: ${data.product}`, 'success');
      // Optional: Update UI to reflect purchase
    } else {
      showNotification(`❌ Error: ${data.error || 'Purchase failed'}`, 'error');
    }
  } catch (error) {
    showNotification(`❌ Network error: ${error.message}`, 'error');
  } finally {
    // Re-enable button
    button.disabled = false;
    button.textContent = originalText;
    button.style.opacity = '1';
    button.style.cursor = 'pointer';
  }
}

// Add smooth scroll behavior
document.addEventListener('DOMContentLoaded', function() {
  // Smooth scroll for anchor links
  document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
      e.preventDefault();
      const target = document.querySelector(this.getAttribute('href'));
      if (target) {
        target.scrollIntoView({ behavior: 'smooth' });
      }
    });
  });
});
