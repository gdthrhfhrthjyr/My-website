function updateBattleInfo(data) {
    console.log('Opdaterer kamp info med:', data);
    const statusContainer = document.getElementById('status-container');
    const scoreContainer = document.getElementById('score-container');
    const scheduleContainer = document.getElementById('schedule-container');
    const errorContainer = document.getElementById('error-container');

    // Ryd tidligere fejlmeddelelser
    errorContainer.innerHTML = '';

    // Opdater status
    let statusText = 'Ukendt Status';
    let statusClass = '';
    if (data && data.status) {
        switch (data.status) {
            case 'in_progress':
                statusText = 'Kamp Igangværende';
                statusClass = 'match-in-progress';
                break;
            case 'canceled':
                statusText = 'Kamp Annulleret';
                statusClass = 'canceled';
                break;
            case 'paused':
                statusText = 'Kamp Pauset';
                statusClass = 'paused';
                break;
            case 'scheduled':
                statusText = 'Kamp Planlagt';
                statusClass = 'scheduled';
                break;
            case 'ended':
                statusText = 'Kamp Afsluttet';
                statusClass = 'ended';
                break;
            case 'no_active_battles':
                statusText = 'Ingen Aktive Kampe';
                statusClass = 'no-matches';
                break;
            case 'error':
                statusText = 'Fejl: ' + (data.message || 'Ukendt fejl');
                statusClass = 'error';
                errorContainer.innerHTML = `<div class="alert alert-danger">${data.message || 'En ukendt fejl opstod'}</div>`;
                break;
            default:
                errorContainer.innerHTML = '<div class="alert alert-danger">Fejl: Ukendt kamp status</div>';
        }
    } else {
        errorContainer.innerHTML = '<div class="alert alert-danger">Fejl: Ugyldige kamp data</div>';
    }
    statusContainer.innerHTML = `<div class="battle-status ${statusClass}">${statusText}</div>`;
    console.log('Status opdateret:', statusText);

    // Opdater score (for alle stater undtagen planlagt og annulleret)
    if (data && data.status && data.status !== 'scheduled' && data.status !== 'canceled' && data.score) {
        const teamAName = data.score.team_names?.teamA || 'Hold A';
        const teamBName = data.score.team_names?.teamB || 'Hold B';
        
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
        console.log('Score opdateret:', data.score);
        
        if (data.status === 'ended' && data.winner) {
            scoreContainer.innerHTML += `<div class="winner">Vinder: ${data.winner}</div>`;
        }
    } else if (data && data.status === 'scheduled') {
        const teamAName = data.team_a_name || 'Hold A';
        const teamBName = data.team_b_name || 'Hold B';
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
        scoreContainer.innerHTML = '<p>Ingen score tilgængelig</p>';
        console.log('Score container ryddet');
    }
    // Opdater tidsplan (kun for planlagte kampe)
    if (data && data.status === 'scheduled' && data.scheduledTime) {
        try {
            const scheduledDate = new Date(data.scheduledTime);
            const teamAName = data.team_a_name || 'Hold A';
            const teamBName = data.team_b_name || 'Hold B';
            scheduleContainer.innerHTML = `
                <div class="schedule-info">
                    <i class="far fa-calendar-alt"></i> 
                    ${teamAName} vs ${teamBName}<br>
                    Planlagt til at starte kl. ${scheduledDate.toLocaleTimeString()} den ${scheduledDate.toLocaleDateString()}
                </div>
            `;
            console.log('Tidsplan opdateret:', data.scheduledTime);
        } catch (error) {
            scheduleContainer.innerHTML = '<p>Ugyldig planlagt tid</p>';
            console.error('Fejl ved parsing af planlagt tid:', error);
        }
    } else {
        scheduleContainer.innerHTML = '<p>Ingen tidsplan tilgængelig</p>';
        console.log('Tidsplan container ryddet');
    }

    console.log('Kamp info opdatering afsluttet');
}

function fetchBattleStatus() {
    fetch('/api/battle-status')
        .then(response => {
            if (!response.ok) {
                throw new Error('Netværksrespons var ikke ok');
            }
            return response.json();
        })
        .then(data => updateBattleInfo(data))
        .catch(error => {
            console.error('Fejl ved hentning af kamp status:', error);
            updateBattleInfo({
                status: 'error',
                message: 'Kunne ikke hente kamp status: ' + error.message
            });
        });
}

// Initial data load
const initialData = JSON.parse(document.getElementById('battle-data').textContent);
updateBattleInfo(initialData);

// Opdater hver 10 sekunder
setInterval(fetchBattleStatus, 10000);
