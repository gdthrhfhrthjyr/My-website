from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

# Initialize SQLAlchemy without creating an instance here
db = SQLAlchemy()

class Battle(db.Model):
    __tablename__ = 'battles'  # Explicitly define table name for clarity

    id = db.Column(db.Integer, primary_key=True)
    status = db.Column(db.String(20), nullable=False)
    team_a_name = db.Column(db.String(100), nullable=False)
    team_b_name = db.Column(db.String(100), nullable=False)
    team_a_score = db.Column(db.Integer, default=0)
    team_b_score = db.Column(db.Integer, default=0)
    scheduled_time = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    winner = db.Column(db.String(50), nullable=True)

    def to_dict(self):
        return {
            'id': self.id,
            'status': self.status,
            'team_a_name': self.team_a_name,
            'team_b_name': self.team_b_name,
            'score': {
                'teamA': self.team_a_score,
                'teamB': self.team_b_score,
                'team_names': {
                    'teamA': self.team_a_name,
                    'teamB': self.team_b_name
                }
            },
            'scheduledTime': self.scheduled_time.isoformat() if self.scheduled_time else None,
            'timestamp': self.created_at.isoformat(),
            'winner': self.winner
        }

def init_app(app):
    """Initialize the SQLAlchemy instance with the Flask app."""
    db.init_app(app)
    
    with app.app_context():
        db.create_all()