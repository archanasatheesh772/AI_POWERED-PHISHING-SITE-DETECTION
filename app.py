from flask import Flask, request, render_template, flash, redirect, url_for, session
from bs4 import BeautifulSoup
import requests
from urllib.parse import urljoin
from controller import Controller
import onetimescript
from db import db
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from db import User 
from db import db, User, PhishingURL ,AuditLog
from admin import admin_bp
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_login import login_user, current_user, logout_user, login_required
from admin import dashboard  # Assuming you have an 'admin.py' file defining the blueprint

app = Flask(__name__)
app.register_blueprint(admin_bp)
app.config['SECRET_KEY'] = 'cycycccycyytcrtdgrtxkeydsdvsdvsv'


app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:rootroot@localhost/phishing_detection'


# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///domains.db'
# Initialize extensions
db.init_app(app)    
migrate = Migrate(app, db)

# # Ensure tables are created
# with app.app_context():
#     db.create_all()
 
# Create tables if they don't exist
with app.app_context():
    db.create_all()


login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


controller = Controller()


from flask import Flask, send_from_directory


# Serve static files from the root
@app.route('/<path:filename>')
def serve_static_files(filename):
    return send_from_directory('static', filename)

# ...existing code...

from controller import Controller
@app.route('/checklink', methods=['GET', 'POST'])
@login_required
def checklink():
    print("checklink page")

    if request.method == 'POST':
        try:
            print("---------inner----------------")
            url = request.form.get('url')
            if not url:
                flash('URL is required!', 'danger')
                return render_template('checklink.html', output='NA')

            print(url)  # Create an instance of the Controller class
            result = controller.main(url)  # Call the main method with the URL argument

            if not result:
                print('Failed to fetch the URL. Please check the URL and try again.', 'danger')
                output = 'NA'
            else:
                print(result)  # This is where your result score is being fetched

                # Extract the trust score from the result
                trust_score = result.get('trust_score')

                # Check if trust_score is less than 60
                if trust_score is not None and trust_score < 60:
                    print(f"Phishing URL detected: {url}")
                    phishing_url = PhishingURL(
                        url=url, 
                        status="Phishing",  # Set the status as "Phishing"
                        flagged=True,  # Flagged as phishing
                        category="Unknown",  # You can assign a category like "Unknown" for now
                        user_id=current_user.id  # Assuming the user is logged in
                    )
                    db.session.add(phishing_url)  # Add it to the database
                    db.session.commit()  # Commit the transaction
                    flash(f'Phishing URL detected and added to the database: {url}', 'danger')
                else:
                    flash(f'The URL is safe with a trust score of {trust_score}.', 'success')

                output = result  # This will be displayed on the page

        except requests.exceptions.RequestException as e:
            print(f"Request error: {e}")
            flash('Failed to fetch the URL. Please check the URL and try again.', 'danger')
            output = 'NA'
        except Exception as e:
            print(f"An error occurred: {e}")
            flash('An unexpected error occurred. Please try again later.', 'danger')
            output = 'NA'
    else:
        output = None

    return render_template('checklink.html', output=output)



@app.route('/preview', methods=['POST'])
def preview():
    try:
        url = request.form.get('url')
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')

        for link in soup.find_all('link'):
            if link.get('href'):
                link['href'] = urljoin(url, link['href'])
  

        for img in soup.find_all('img'):
            if img.get('src'):
                img['src'] = urljoin(url, img['src'])

        return render_template('preview.html', content=soup.prettify())
    except Exception as e:
        return  f"Error: {e}"


@app.route('/source-code', methods=['GET','POST'])
def view_source_code():

    try:
        url = request.form.get('url')
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')
        formatted_html = soup.prettify()
        
        return render_template('source_code.html', formatted_html = formatted_html, url = url)
    
    except Exception as e:
        return  f"Error: {e}"

@app.route('/update-db')
def update_db(): 
    try:
        with app.app_context():
            response = onetimescript.update_db()
            print("Database populated successfully!")
            return response, 200
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return "An error occurred: " + str(e), 500

@app.route('/update-json')
def update_json(): 
    try:
        with app.app_context():
            response = onetimescript.update_json()
            print("JSON updated successfully!")
            return response, 200
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return "An error occurred: " + str(e), 500




@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username_or_email = request.form['username_or_email']
        password = request.form['password']
        
        # Check if the input is an email or username
        if '@' in username_or_email:
            user = User.query.filter_by(email=username_or_email).first()
        else:
            user = User.query.filter_by(username=username_or_email).first()

        # Verify the user and password
        if user and user.password == password:
            session['user_id'] = user.id
            login_user(user)
            flash('Login successful!', 'success')
            
            # Redirect based on user role (admin or regular user)
            if user.role == 'admin':
                return redirect(url_for('admin.dashboard'))  # Admin redirection
            else:
                return redirect(url_for('index'))  # Regular user redirection

        flash('Login failed. Check your username and/or password.', 'danger')
    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            print("User with this email already exists!")
            return redirect(url_for('signup'))
        new_user = User(username=username, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()
        flash('Signup successful! Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/',  methods=['GET','POST'])
def index():
    return render_template('index.html')


@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/blog')
def blog():
    return render_template('blog.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/FAQ')
def faq():
    return render_template('FAQ.html')

@app.route('/feature')
def feature():
    return render_template('feature.html')

@app.route('/service')
def service():
    return render_template('service.html')

@app.route('/team')
def team():
    return render_template('team.html')

@app.route('/testimonial')
def testimonial():
    return render_template('testimonial.html')


def page_not_found(e):
    return render_template('404.html'), 404














#test
import qrcode  

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask import Flask
from flask_caching import Cache
from db import Url
import qrcode
import io
import os
import shortuuid
cache = Cache(app)
limiter = Limiter(get_remote_address)


@app.errorhandler(429)
def ratelimit_handler(e):
    return render_template('429.html'), 429

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('500.html'), 500



def generate_qr_code(url):
    img = qrcode.make(url)
    img_io = io.BytesIO()
    img.save(img_io, 'PNG')
    img_io.seek(0)
    return img_io


@app.route('/generate_qr_code', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def generate_qr_code_view():
    if request.method == 'POST':
        long_url = request.form['long_url']
        if long_url[:4] != 'http':
            long_url = 'http://' + long_url
        
        # Generate the QR code for the long URL
        img_io = generate_qr_code(long_url)
        
        # Save the QR code image to a file
        qr_code_path = f"qr_codes/{shortuuid.uuid()[:6]}.png"  # Generating a random filename for each QR
        img_io.seek(0)
        with open(os.path.join('static', qr_code_path), "wb") as f:
            f.write(img_io.read())

        return render_template('qr_code_generated.html', qr_code_path=qr_code_path)

    return render_template('generate_qr_code.html')



@app.route('/analytics/<short_url>')
@login_required
@cache.cached(timeout=50)
def url_analytics(short_url):
    url = Url.query.filter_by(short_url=short_url).first()
    if url:
        return render_template('analytics.html', url=url)
    return 'URL not found.'


@app.route('/urlshortner', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def urlshortner():
    if request.method == 'POST':
        long_url = request.form['long_url']
        custom_url = request.form['custom_url'] or None
        if custom_url:
            existing_url = Url.query.filter_by(custom_url=custom_url).first()
            if existing_url:
                flash ('That custom URL already exists. Please try another one!')
                return redirect(url_for('urlshortner'))
            short_url = custom_url
        elif long_url[:4] != 'http':
            long_url = 'http://' + long_url
        else:
            short_url = shortuuid.uuid()[:6]
        url = Url(long_url=long_url, short_url=short_url, custom_url=custom_url, user_id=current_user.id)
        db.session.add(url)
        db.session.commit()
        return redirect(url_for('linkshortnerhistory'))

    urls = Url.query.order_by(Url.created_at.desc()).limit(10).all()
    dynamic_content = " "
    delivery_message = " "
    order_link = "#"
    youtube_link = " "

    return render_template('urlshortner.html', urls=urls,dynamic_content=dynamic_content,
                           delivery_message=delivery_message,
                           order_link=order_link,
                           youtube_link=youtube_link)



@app.route("/linkshortnerhistory")
@login_required
@cache.cached(timeout=50)
def linkshortnerhistory():
    urls = Url.query.filter_by(user_id=current_user.id).order_by(Url.created_at.desc()).all()
    host = request.host_url
    return render_template('linkshortnerhistory.html', urls=urls, host=host)



@app.route('/<short_url>')
@cache.cached(timeout=50)
def redirect_url(short_url):
    url = Url.query.filter_by(short_url=short_url).first()
    if url:
        url.clicks += 1
        db.session.commit()
        return redirect(url.long_url)
    return 'URL not found.'


@app.route('/qr_code/<short_url>')
def generate_qr_code_url(short_url):
    url = Url.query.filter_by(short_url=short_url).first()
    if url:
        img_io = generate_qr_code(request.host_url + url.short_url)
        return img_io.getvalue(), 200, {'Content-Type': 'image/png'}
    return 'URL not found.'




@app.route('/history')
@login_required
@cache.cached(timeout=50)
def link_history():
    urls = Url.query.filter_by(user_id=current_user.id).order_by(Url.created_at.desc()).all()
    host = request.host_url
    return render_template('history.html', urls=urls, host=host)




@app.route('/delete/<int:id>')
@login_required
def delete(id):
    url = Url.query.get_or_404(id)
    if url:
        db.session.delete(url)
        db.session.commit()
        return redirect(url_for('dashboard'))
    return 'URL not found.'



@app.route('/edit/<int:id>', methods=['GET', 'POST'])
@login_required
def edit_url(id):
    url = Url.query.get_or_404(id)
    if url:
        if request.method == 'POST':
            custom_url = request.form['custom_url']
            if custom_url:
                existing_url = Url.query.filter_by(custom_url=custom_url).first()
                if existing_url:
                    flash ('That custom URL already exists. Please try another one.')
                    return redirect(url_for('edit_url', id=id))
                url.custom_url = custom_url
                url.short_url = custom_url
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('dashboard'))
        return render_template('edit.html', url=url)
    return 'URL not found.'

#Check number of users and links created
@app.route('/stats')
def stats():
    users = User.query.count()
    links = Url.query.count()
    clicks = Url.query.with_entities(func.sum(Url.clicks)).scalar()

    return render_template('stats.html', users=users, links=links, clicks=clicks)


@app.route('/safe-preview', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def safe_preview_view():
    if request.method == 'POST':
        target_url = request.form['url']
        
        # Simple validation: ensure the URL starts with http/https
        if target_url[:4] != 'http' and target_url[:5] != 'https':
            return render_template('safe_preview_form.html', error="Please enter a valid URL starting with http:// or https://")
        
        # Fetch content from the target URL safely (e.g., using requests)
        try:
            response = requests.get(target_url, timeout=10)
            # You can add logic to check for certain conditions to filter unsafe content
            if response.status_code == 200:
                page_content = response.text
            else:
                return render_template('safe_preview_form.html', error="Could not fetch the URL content. Please try again.")
        except requests.exceptions.RequestException as e:
            return render_template('safe_preview_form.html', error=f"Error fetching the content: {e}")

        return render_template('safe_preview_result.html', url=target_url, page_content=page_content)

    return render_template('safe_preview_form.html')



if __name__ == '__main__':
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
