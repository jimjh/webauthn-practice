"""This file should never be imported."""
import logging
from flask import Flask
from flask.logging import default_handler

from hier.extensions import db
from hier import views
from hier.secrets import SECRET_KEY, DATABASE_URI


def create_app():
    flask_app = Flask('webauthn-practice')
    flask_app.secret_key = SECRET_KEY
    flask_app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URI
    flask_app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    _register_extensions(flask_app)
    _register_blueprints(flask_app)
    logging.getLogger().addHandler(default_handler)
    return flask_app


def _register_extensions(flask_app):
    db.init_app(flask_app)


def _register_blueprints(flask_app):
    flask_app.register_blueprint(views.blueprint)
