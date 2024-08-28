from website import create_app

# Importing the auth blueprint
from website.auth import auth

app = create_app()

# Registering the auth blueprint with the app
app.register_blueprint(auth, name='auth_blueprint')

if __name__ == '__main__':
    app.run(debug=True , port=4091)