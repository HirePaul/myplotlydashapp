// assets/script.js

function updateViewportWidth() { 
    const width = window.innerWidth || document.documentElement.clientWidth || document.body.clientWidth;
    const storeElement = document.getElementById('viewport-width-store');

    // Use setProps to update the `data` prop directly if available
    if (storeElement && storeElement.setProps) {
        storeElement.setProps({ data: width });
    }
    console.log('Window resized!');
}

// Listen for window resize and update viewport width
window.addEventListener("resize", updateViewportWidth);

// Trigger it once on page load
updateViewportWidth();
