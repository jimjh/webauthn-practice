from flask_sqlalchemy import SQLAlchemy
db = SQLAlchemy()   # note: not passing flask app here to avoid circular imports
