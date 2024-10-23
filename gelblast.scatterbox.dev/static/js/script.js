function updateBattleInfo(data) {
    console.log('Updating battle info with:', data);
    const statusContainer = document.getElementById('status-container');
    const scoreContainer = document.getElementById('score-container');
    const scheduleContainer = document.getElementById('schedule-container');
    const errorContainer = document.getElementById('error-container');

    // Clear previous error messages
    errorContainer.innerHTML = '';

    // Update status
    let statusText = 'Unknown Status';
    let statusClass = '';
    if (data && data.status) {
        switch (data.status) {
            case 'in_progress':
                statusText = 'Match In Progress';
                statusClass = 'match-in-progress';
                break;
            case 'canceled':
                statusText = 'Match Canceled';
                statusClass = 'canceled';
                break;
            case 'paused':
                statusText = 'Match Paused';
                statusClass = 'paused';
                break;
            case 'scheduled':
                statusText = 'Match Scheduled';
                statusClass = 'scheduled';
                break;
            case 'ended':
                statusText = 'Match Ended';
                statusClass = 'ended';
                break;
            case 'no_active_battles':
                statusText = 'No Active Battles';
                statusClass = 'no-matches';
                break;
            case 'error':
                statusText = 'Error: ' + (data.message || 'Unknown error');
                statusClass = 'error';
                errorContainer.innerHTML = `<div class="alert alert-danger">${data.message || 'An unknown error occurred'}</div>`;
                break;
            default:
                errorContainer.innerHTML = '<div class="alert alert-danger">Error: Unknown battle status</div>';
        }
    } else {
        errorContainer.innerHTML = '<div class="alert alert-danger">Error: Invalid battle data</div>';
    }
    statusContainer.innerHTML = `<div class="battle-status ${statusClass}">${statusText}</div>`;
    console.log('Status updated:', statusText);

    // Update score (for all states except scheduled and canceled)
    if (data && data.status && data.status !== 'scheduled' && data.status !== 'canceled' && data.score) {
        const teamAName = data.score.team_names?.teamA || 'Team A';
        const teamBName = data.score.team_names?.teamB || 'Team B';
        
        scoreContainer.innerHTML = `
            <div class="team-score">
                <div class="team">
                    <div class="team-name">${teamAName}</div>
                    <div class="score">${data.score.teamA || 0}</div>
                </div>
                <div class="vs">VS</div>
                <div class="team">
                    <div class="team-name">${teamBName}</div>
                    <div class="score">${data.score.teamB || 0}</div>
                </div>
            </div>
        `;
        console.log('Score updated:', data.score);
        
        if (data.status === 'ended' && data.winner) {
            scoreContainer.innerHTML += `<div class="winner">Winner: ${data.winner}</div>`;
        }
    } else if (data && data.status === 'scheduled') {
        const teamAName = data.team_a_name || 'Team A';
        const teamBName = data.team_b_name || 'Team B';
        scoreContainer.innerHTML = `
            <div class="team-score">
                <div class="team">
                    <div class="team-name">${teamAName}</div>
                    <div class="vs">VS</div>
                    <div class="team-name">${teamBName}</div>
                </div>
            </div>
        `;
    } else {
        scoreContainer.innerHTML = '<p>No score available</p>';
        console.log('Score container cleared');
    }

    // Update schedule (only for scheduled matches)
    if (data && data.status === 'scheduled' && data.scheduledTime) {
        try {
            const scheduledDate = new Date(data.scheduledTime);
            const teamAName = data.team_a_name || 'Team A';
            const teamBName = data.team_b_name || 'Team B';
            scheduleContainer.innerHTML = `
                <div class="schedule-info">
                    <i class="far fa-calendar-alt"></i> 
                    ${teamAName} vs ${teamBName}<br>
                    Scheduled to start at ${scheduledDate.toLocaleTimeString()} on ${scheduledDate.toLocaleDateString()}
                </div>
            `;
            console.log('Schedule updated:', data.scheduledTime);
        } catch (error) {
            scheduleContainer.innerHTML = '<p>Invalid scheduled time</p>';
            console.error('Error parsing scheduled time:', error);
        }
    } else {
        scheduleContainer.innerHTML = '<p>No schedule available</p>';
        console.log('Schedule container cleared');
    }

    console.log('Battle info update completed');
}

function fetchBattleStatus() {
    fetch('/api/battle-status')
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => updateBattleInfo(data))
        .catch(error => {
            console.error('Error fetching battle status:', error);
            updateBattleInfo({
                status: 'error',
                message: 'Failed to fetch battle status: ' + error.message
            });
        });
}

// Initial data load
const initialData = JSON.parse(document.getElementById('battle-data').textContent);
updateBattleInfo(initialData);

// Update every 10 seconds
setInterval(fetchBattleStatus, 10000);
