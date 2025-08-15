// Updated JS
document.addEventListener('DOMContentLoaded', function () {
    const viewTypeSelect = document.getElementById('viewType');
    const gridContainer = document.querySelector('.grid-container');
    const ctx = document.getElementById('moodChart').getContext('2d');
    const loadingSpinner = document.getElementById('loadingSpinner');
    let moodChart;

    // Add the missing updateChart function
    function updateChart(moods) {
        const moodCounts = {};

        // Process mood data
        moods.forEach(mood => {
            const label = mood.mood_label || 'Unknown';
            moodCounts[label] = (moodCounts[label] || 0) + 1;
        });

        const labels = Object.keys(moodCounts);
        const data = Object.values(moodCounts);

        // Destroy existing chart instance
        if (moodChart) {
            moodChart.destroy();
        }

        // Create new chart
        moodChart = new Chart(ctx, {
            type: 'pie',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Mood Distribution',
                    data: data,
                    backgroundColor: [
                        '#4caf50', '#f44336', '#ff9800', '#2196f3', '#9c27b0', '#3f51b5'
                    ],
                    borderColor: '#ffffff',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: 'bottom'
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                return `${context.label}: ${context.parsed}`;
                            }
                        }
                    }
                }
            }
        });
    }


    function fetchMoodTrends(viewType) {
        loadingSpinner.classList.remove('hidden');
        fetch('/get-mood-trends', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ user_id: userId, view_type: viewType })
        })
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            loadingSpinner.classList.add('hidden');
            console.log('Received data:', data); // Debug log
            if (data.moods && data.moods.length > 0) {
                updateChart(data.moods);
                renderMoodGrid(data.moods);
            } else {
                showMessage('No mood data available');
            }
        })
        .catch(error => {
            console.error('Fetch error:', error);
            loadingSpinner.classList.add('hidden');
            showMessage('Failed to load data. Please try again.');
        });
    }
    
    // Add this helper function
    function showMessage(text) {
        const messageDiv = document.createElement('div');
        messageDiv.className = 'error-message';
        messageDiv.textContent = text;
        document.querySelector('.container').appendChild(messageDiv);
        
        // Remove message after 5 seconds
        setTimeout(() => messageDiv.remove(), 5000);
    }

    function renderMoodGrid(moods) {
        // Clear existing grid rows
        const existingRows = document.querySelectorAll('.mood-row');
        existingRows.forEach(row => row.remove());

        // Group moods by type and day
        const moodData = moods.reduce((acc, mood) => {
            const day = new Date(mood.timestamp).toLocaleDateString('en-US', { weekday: 'short' });
            if (!acc[mood.mood_label]) {
                acc[mood.mood_label] = {
                    counts: {},
                    total: 0
                };
            }
            acc[mood.mood_label].counts[day] = (acc[mood.mood_label].counts[day] || 0) + 1;
            acc[mood.mood_label].total++;
            return acc;
        }, {});

        // Create grid rows
        Object.entries(moodData).forEach(([moodType, data]) => {
            const row = document.createElement('div');
            row.className = 'mood-row';
            
            // Category cell
            const categoryCell = document.createElement('div');
            categoryCell.className = 'mood-cell category';
            categoryCell.textContent = moodType;
            
            // Day cells
            const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
            const dayCells = days.map(day => {
                const cell = document.createElement('div');
                cell.className = 'mood-cell';
                cell.textContent = data.counts[day] || '-';
                return cell;
            });

            // Append all cells
            row.append(categoryCell, ...dayCells);
            gridContainer.appendChild(row);
        });
    }

    // Keep the existing chart update logic
    // ... (rest of your existing chart code)

    viewTypeSelect.addEventListener('change', () => fetchMoodTrends(viewTypeSelect.value));
    fetchMoodTrends(viewTypeSelect.value);
});