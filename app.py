import os

import sqlite3
from flask import Flask, flash, redirect, render_template, request, session, g
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd 

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

DATABASE = 'finance.db'
PORTFOLIO_DATABASE = 'portfolio.db'
TRANSACTIONS_DATABASE = 'transactions.db'  

# Utilizes the g object in flask to return a connection to the finance database when needed
def get_db():
    if 'db' not in g: 
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute(f"ATTACH DATABASE '{PORTFOLIO_DATABASE}' AS portfolio_db")
        g.db.execute(f"ATTACH DATABASE '{TRANSACTIONS_DATABASE}' AS transactions_db") 
    return g.db

# Updates the column current_prices in the portfolio database with the correct current prices of each stock in a user's portfolio
def update_prices():
    user_id = session["user_id"] 
    db = get_db()
    portfolio_rows = db.execute("SELECT symbol FROM portfolio WHERE user_id = ?", ((user_id),)).fetchall()

    for row in portfolio_rows:
        temp = lookup(row["symbol"])
        db.execute("UPDATE portfolio SET current_price = ? WHERE user_id = ? AND symbol = ?", (temp["price"], user_id, row["symbol"],))
    db.commit() 

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Handles the route to the homepage - sending the html file the needed information to display
@app.route("/") 
@login_required
def index():
    update_prices() #updates current_prices column in database so accurate information is displayed on the home screen
    """Show portfolio of stocks"""
    user_id = session["user_id"]
    db = get_db()
    
    portfolios = db.execute('''SELECT symbol, shares, purchase_price, current_price, (shares * current_price) 
                            AS total FROM portfolio where user_id = ?''', (user_id,)).fetchall() 
    
    cash_row = db.execute('SELECT cash FROM users where id = ?', (user_id, )).fetchone()
    if cash_row == None:
        cash_available = 0
    else:
        cash_available = cash_row['cash']

    total_cash = cash_available
    stock_cash = db.execute('SELECT (shares * current_price) AS total FROM portfolio where user_id = ?', (user_id,)).fetchall() 
    for row in stock_cash:
        total_cash += row['total'] 

    total_net_gain = 0
    for portfolio in portfolios:
        total_net_gain += portfolio['total'] - (portfolio['shares'] * portfolio['purchase_price']) 
        
    return render_template('home.html', portfolios=portfolios, cash_available=cash_available, total_cash=total_cash, total_net_gain=total_net_gain)  

# Handles the route to the buy page - allows the user to purchase the stock  
@app.route("/buy", methods=["GET", "POST"]) 
@login_required
def buy():
    """Buy shares of stock"""
    user_id = session["user_id"]
    db = get_db()

    if request.method == 'POST':

        if not request.form.get("symbol"):
            return apology("Must Provide Correct Stock Ticker", 403)
        
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares")) 
        
        if shares <= 0 or not isinstance(shares, int):
            return apology("Must enter a valid amount of shares", 403) 
        
        symbol_lookup = lookup(symbol)
        if symbol_lookup == None:
            return apology("Must Provide Correct Stock Ticker", 403)
        
        price = symbol_lookup["price"]

        cash_hand = db.execute("SELECT cash FROM users WHERE id = ?", (user_id,)).fetchone() 
        purchase_cost = shares * price
        
        # checks that user has enough on hand chas to make the purchase 
        if purchase_cost > cash_hand["cash"]: 
            return apology("You Can't Afford This Purchase", 403) 

        rows_symbol = db.execute("SELECT * FROM portfolio WHERE user_id = ? AND symbol = ?", (user_id, symbol)).fetchone() 
        if rows_symbol == None: 
            db.execute('''INSERT INTO portfolio (user_id, symbol, shares, purchase_price, current_price, total) 
                       VALUES (?, ?, ?, ?, ?, ?)''', (user_id, symbol, shares, price, price, (shares * price))) 
        else: 
            prev_total = rows_symbol["total"] 
            prev_shares = rows_symbol["shares"] 
            new_total = prev_total + purchase_cost
            new_shares = shares + prev_shares
            purchase_price = new_total / new_shares 
            db.execute('UPDATE portfolio SET shares = ?, purchase_price = ?, current_price = ?, total = ? WHERE user_id = ? AND symbol = ?',
                       (new_shares, purchase_price, price, new_total, user_id, symbol)) 
        
        #Updates on hand cash in user data base
        new_cash_hand = cash_hand["cash"] - purchase_cost 
        db.execute('UPDATE users SET cash = ? WHERE id = ?', (new_cash_hand, user_id,)) 

        db.execute('''INSERT INTO transactions (user_id, transaction_type, symbol, price_at_transaction, shares, total) 
                   VALUES (?, ?, ?, ?, ?, ?)''', (user_id, 'buy', symbol, price, shares, (price * shares)))  
        db.commit() 

        return render_template("buy.html", shares=shares, symbol=symbol, price=price)

    else:
        return render_template("buy.html") 


@app.route("/transactions")
@login_required
def history():
    """Show history of transactions"""
    user_id = session["user_id"]
    db = get_db()

    transactions = db.execute('''SELECT transaction_type, symbol, price_at_transaction, shares, 
                              (shares * price_at_transaction) AS total FROM transactions WHERE user_id = ?''', (user_id,)).fetchall()
    
    return render_template("transactions.html", transactions=transactions) 

# Handles the login route - checking if the user gave a username and password along with checking with the finance.db if it is correct 
@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        db = get_db()
        rows = db.execute("SELECT * FROM users WHERE username = ?", (request.form.get("username"),)).fetchall() 

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Updates portfolio database with current prices


        # Redirect user to home page
        return redirect("/") 

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

# Handles the logout route - simpily cleas the session and redirects to the login page 
@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")

# Handles the quote route - where it takes the ticker symbol that the user gave and gets the current price of the stock and sends 
# this information to the html file to be displayed
@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":

        if not request.form.get("symbol"):
            return apology("Must Provide Correct Stock Ticker", 403)
        
        ticker_symbol = request.form.get("symbol")
        symbol_lookup = lookup(ticker_symbol)

        if symbol_lookup == None:
            return apology("Must Provide Correct Stock Ticker", 403) 
        
        symbol = symbol_lookup["symbol"] 
        price = symbol_lookup["price"]

        return render_template("/quote.html", symbol=symbol, price=price) 
    
    else:
        return render_template("/quote.html")

# Handles the register route - gets a username and password from the user and checks if the username is available 
@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "POST":

        if not request.form.get("username"):
            return apology("must provide username", 403)
        
        elif not request.form.get("password"):
            return apology("must provide a password", 403)
        
        username = request.form.get("username")
        password = request.form.get("password")
        hash_password = generate_password_hash(password, method='pbkdf2:sha256')
        
        db = get_db()
        rows = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchall()

        if len(rows) > 0:
            return apology("username already taken", 403)
        else:
            db.execute("INSERT INTO users(username, hash) VALUES(?, ?)", (username, hash_password))
            db.commit()
        
        return redirect("/login")
    
    else:
        return render_template("register.html")
        

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    user_id = session["user_id"]
    db = get_db() 

    if request.method == 'POST':

        if not request.form.get("symbol"):
            return apology("Must Provide Correct Stock Ticker", 403)
        
        symbol = request.form.get("symbol")
        shares = int(request.form.get("shares"))

        symbol_lookup = lookup(symbol)
        if symbol_lookup == None:
            return apology("Must Provide Correct Stock Ticker", 403) 
        
        current_shares = db.execute('SELECT shares FROM portfolio WHERE user_id = ? AND symbol = ?', (user_id, symbol)).fetchone()
        if current_shares is None:
            return apology("You do not own any shares of this stock", 403)
        
        if shares > current_shares["shares"]: 
            return apology("Must enter a valid amount of shares", 403) 
        
        price = symbol_lookup["price"]

        cash_hand_row = db.execute("SELECT cash FROM users WHERE id = ?", (user_id,)).fetchone() 
        money_gained = shares * price
        total_cash = cash_hand_row["cash"] + money_gained

        db.execute('UPDATE users SET cash = ? WHERE id = ?', (total_cash, user_id))

        if current_shares["shares"] == shares:
            db.execute('DELETE FROM portfolio WHERE user_id = ? AND symbol = ?', (user_id, symbol)) 
        else:
            new_shares = current_shares["shares"] - shares
            prev_total = db.execute('SELECT total FROM portfolio WHERE user_id = ? AND symbol = ?', (user_id, symbol)).fetchone()
            new_total = prev_total["total"] - money_gained 
            db.execute('UPDATE portfolio SET shares = ?, total = ? WHERE user_id = ? AND symbol = ?', (new_shares, new_total, user_id, symbol))

        db.execute('''INSERT INTO transactions (user_id, transaction_type, symbol, price_at_transaction, shares, total) 
                   VALUES (?, ?, ?, ?, ?, ?)''', (user_id, 'sell', symbol, price, shares, (price * shares)))  
        db.commit() 
        
        return render_template("sell.html", shares=shares, symbol=symbol, price=price) 
    
    else:
        return render_template("sell.html") 


if __name__ == '__main__':
    app.run(debug=True)

