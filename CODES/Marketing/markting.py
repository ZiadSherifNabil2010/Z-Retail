@app.route('/marketing')
@login_required
@role_required(ROLES['marketing'], ROLES['HQ'],ROLES['developer'])
def marketing_interface():
    return render_template('marketing.html')
