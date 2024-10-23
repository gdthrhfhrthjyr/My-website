from flask import Flask, render_template, jsonify, request, redirect, url_for, session
import os
from datetime import datetime, timedelta
from functools import wraps
from models import db, Battle
from dotenv import load_dotenv

load_dotenv('/var/Site-resources/.envs/gelblast.scatterbox.dev/.env')

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") 

# Configure database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///var/sites/gelblast.scatterbox.dev/instance/battles.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

# Admin credentials (in a real-world scenario, use a database and proper hashing)
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")

# Define login_required decorator before using it
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

def get_current_battle():
    return Battle.query.filter(Battle.status.in_(['in_progress', 'paused'])).first()

def get_scheduled_battles():
    return Battle.query.filter_by(status='scheduled').order_by(Battle.scheduled_time).all()

def get_last_completed_battle():
    return Battle.query.filter(Battle.status.in_(['ended', 'canceled'])).order_by(Battle.updated_at.desc()).first()

@app.route('/api/battle-status')
def battle_status():
    try:
        # First, check for current battle
        current_battle = get_current_battle()
        if current_battle:
            return jsonify(current_battle.to_dict())
        
        # If no current battle, get the next scheduled battle
        next_battle = Battle.query.filter_by(status='scheduled').order_by(Battle.scheduled_time).first()
        if next_battle:
            return jsonify(next_battle.to_dict())
            
        # If no active or scheduled battles, get the most recent ended/canceled battle
        last_battle = get_last_completed_battle()
        if last_battle:
            return jsonify(last_battle.to_dict())
            
        # If no battles at all, return a default response
        return jsonify({
            'status': 'no_active_battles',
            'message': 'No active, scheduled, or completed battles found'
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/end-match', methods=['POST'])
@login_required
def end_match():
    try:
        current_battle = get_current_battle()
        if not current_battle:
            return jsonify({'error': 'No active battle found'}), 404

        # Determine the winner based on scores
        if current_battle.team_a_score > current_battle.team_b_score:
            current_battle.winner = current_battle.team_a_name
        elif current_battle.team_b_score > current_battle.team_a_score:
            current_battle.winner = current_battle.team_b_name
        else:
            current_battle.winner = "Tie"

        current_battle.status = 'ended'
        db.session.commit()
        return jsonify(current_battle.to_dict())
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/start-battle/<int:match_id>', methods=['POST'])
@login_required
def start_battle(match_id):
    try:
        # Check if there's already an active battle
        if get_current_battle():
            return jsonify({'error': 'Cannot start a new battle while one is in progress'}), 400
            
        battle = Battle.query.get_or_404(match_id)
        if battle.status != 'scheduled':
            return jsonify({'error': 'Can only start scheduled battles'}), 400
            
        battle.status = 'in_progress'
        db.session.commit()
        return jsonify(battle.to_dict())
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/update-score', methods=['POST'])
@login_required
def update_score():
    try:
        data = request.get_json()
        team = data.get('team')
        change = data.get('change')
        
        current_battle = get_current_battle()
        if not current_battle:
            return jsonify({'error': 'No active battle found'}), 404
            
        if team == 'a':
            current_battle.team_a_score = max(0, current_battle.team_a_score + change)
        elif team == 'b':
            current_battle.team_b_score = max(0, current_battle.team_b_score + change)
            
        db.session.commit()
        return jsonify(current_battle.to_dict())
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/toggle-pause', methods=['POST'])
@login_required
def toggle_pause():
    try:
        current_battle = get_current_battle()
        if not current_battle:
            return jsonify({'error': 'No active battle found'}), 404
            
        current_battle.status = 'paused' if current_battle.status == 'in_progress' else 'in_progress'
        db.session.commit()
        return jsonify(current_battle.to_dict())
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/cancel-match', methods=['POST'])
@login_required
def cancel_match():
    try:
        current_battle = get_current_battle()
        if not current_battle:
            return jsonify({'error': 'No active battle found'}), 404
            
        current_battle.status = 'canceled'
        db.session.commit()
        return jsonify(current_battle.to_dict())
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/cancel-scheduled-match/<int:match_id>', methods=['POST'])
@login_required
def cancel_scheduled_match(match_id):
    try:
        battle = Battle.query.get_or_404(match_id)
        if battle.status != 'scheduled':
            return jsonify({'error': 'Can only cancel scheduled matches'}), 400
            
        battle.status = 'canceled'
        db.session.commit()
        return jsonify(battle.to_dict())
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.template_filter('datetime')
def format_datetime(value, format="%Y-%m-%d %H:%M:%S"):
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except ValueError:
            return "Invalid date"
    return value.strftime(format)

@app.route('/')
def index():
    try:
        current_battle = get_current_battle()
        if current_battle:
            battle_data = current_battle.to_dict()
        else:
            next_battle = Battle.query.filter_by(status='scheduled').order_by(Battle.scheduled_time).first()
            if next_battle:
                battle_data = next_battle.to_dict()
            else:
                last_battle = get_last_completed_battle()
                battle_data = last_battle.to_dict() if last_battle else {'status': 'no_active_battles'}
        
        return render_template('index.html', battle_data=battle_data)
    except Exception as e:
        return render_template('500.html', error=str(e)), 500

@app.route('/history')
def history():
    try:
        completed_battles = Battle.query.filter_by(status='ended').order_by(Battle.created_at.desc()).all()
        return render_template('history.html', battle_history=[b.to_dict() for b in completed_battles])
    except Exception as e:
        return render_template('500.html', error=str(e)), 500

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['logged_in'] = True
            return redirect(url_for('admin_panel'))
        else:
            return render_template('admin_login.html', error="Invalid credentials")
    return render_template('admin_login.html')

@app.route('/admin/logout')
def admin_logout():
    session.pop('logged_in', None)
    return redirect(url_for('index'))

@app.route('/admin')
@login_required
def admin_panel():
    current_battle = get_current_battle()
    scheduled_battles = get_scheduled_battles()
    return render_template('admin_panel.html', current_battle=current_battle, scheduled_battles=scheduled_battles)

@app.route('/admin/create_battle', methods=['POST'])
@login_required
def create_battle():
    try:
        # Don't allow creating a new battle if one is in progress
        if get_current_battle():
            return render_template('500.html', error="Cannot create a new battle while one is in progress"), 400
        
        # Get form data
        match_date = request.form['match_date']
        match_time = request.form['match_time']
        team_a_name = request.form['team_a_name']
        team_b_name = request.form['team_b_name']
        
        # Combine date and time
        scheduled_time = datetime.strptime(f"{match_date} {match_time}", "%Y-%m-%d %H:%M")
        
        # Create new battle
        battle = Battle(
            status='scheduled',
            team_a_name=team_a_name,
            team_b_name=team_b_name,
            team_a_score=0,
            team_b_score=0,
            scheduled_time=scheduled_time
        )
        db.session.add(battle)
        db.session.commit()
        return redirect(url_for('admin_panel'))
    except Exception as e:
        return render_template('500.html', error=str(e)), 500

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html', error=str(e)), 500

# Create database tables
with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=3004)
