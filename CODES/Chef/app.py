@app.route('/chef')
@login_required
@role_required(ROLES['chef'], ROLES['HQ'],ROLES['developer'])
def chef_interface():
    inventory_data = load_inventory_data()
    categories = load_categories_data()
    branches = get_all_branches()
    
    return render_template('chef.html', categories=categories, inventory=inventory_data, branches=branches)

@app.route('/submit_report', methods=['POST'])
@login_required
def submit_report():
    if request.method == 'POST':
        try:
            # Extract the form data
            report_type = request.form.get('report_type')
            date = request.form.get('date')
            chef_name = request.form.get('chef_name')
            selected_items = json.loads(request.form.get('selected_items', '[]'))  # Items from form (JSON)
            from_branch = request.form.get('from_branch')
            to_branch = request.form.get('to_branch')

            if not selected_items:
                flash('الرجاء إضافة عنصر واحد على الأقل', 'error')
                return redirect(url_for('chef_interface'))

            print(f"Processing report - Type: {report_type}, Items Count: {len(selected_items)}")
            print("Selected Items: ", selected_items)  # Debugging step: Check structure

            # Load inventory and existing reports to generate report ID
            inventory_data = load_inventory_data()
            existing_reports = get_all_reports()
            report_base_number = len(existing_reports) + 1

            # Generate a unique report ID based on report type
            if report_type == 'creation':
                parent_report_id = f"N-{report_base_number:03}"
            elif report_type == 'waste':
                parent_report_id = f"E-{report_base_number:03}"
            elif report_type == 'transfer':
                parent_report_id = f"T-{report_base_number:03}"
            else:
                parent_report_id = f"U-{report_base_number:03}"

            print(f"Generated Parent Report ID for this submission: {parent_report_id}")

            success_count = 0  # Counter for successfully saved reports
            for idx, item_data in enumerate(selected_items, 1):
                print(item_data)  # Debugging step: Check structure of each item

                # Generate unique item ID that includes parent report ID
                item_report_id = f"{parent_report_id}-{idx:02d}"

                # Match the item from inventory using SKU
                matched_item = next(
                    (item for item in inventory_data
                     if str(item.get('ISBN', '')).split('.')[0].strip() == str(item_data['sku']).strip()),
                    None
                )

                if not matched_item:
                    print(f"Item not found in inventory: {item_data['sku']}")
                    continue

                # Construct the report data for each item
                report_data = {
                    'parent_report_id': parent_report_id,
                    'report_id': item_report_id,
                    'sku': item_data['sku'],
                    'item_name': item_data['name'],
                    'report_type': report_type,
                    'quantity': item_data['quantity'],
                    'unit': item_data['unit'],
                    'date': date,
                    'chef_name': chef_name,
                    'status': 'Pending',
                    'branch': session['user']['branch']  # Include branch for report filtering
                }

                # Add transfer-specific data
                if report_type == 'transfer':
                    report_data['from_branch'] = from_branch
                    report_data['to_branch'] = to_branch

                print(f"Saving item to report ID {item_report_id}: {report_data['item_name']}")

                # Save the report data to the Google Sheet
                if save_report(report_data, item_report_id):
                    success_count += 1

            # Handle feedback to the user after the submission
            if success_count == len(selected_items):
                if len(selected_items) > 1:
                    item_ids = [f"{parent_report_id}-{i:02d}" for i in range(1, len(selected_items) + 1)]
                    flash(f'Report submitted successfully (Parent Report ID: {parent_report_id}, Item IDs: {", ".join(item_ids)})', 'success')
                else:
                    flash(f'Report submitted successfully (Parent Report ID: {parent_report_id}, Item ID: {parent_report_id}-01)', 'success')
            elif success_count > 0:
                successful_items = [f"{parent_report_id}-{i:02d}" for i in range(1, success_count + 1)]
                flash(f'Successfully submitted {success_count} out of {len(selected_items)} items in report {parent_report_id} (Item IDs: {", ".join(successful_items)})', 'warning')
            else:
                flash('Error submitting report', 'error')

            # Redirect back to the chef interface after submission
            return redirect(url_for('chef_interface'))
        except Exception as e:
            # Print error details in case of failure
            print(f"Error in submit_report: {e}")
            import traceback
            print(f"Traceback: {traceback.format_exc()}")
            flash('An error occurred while submitting the report. Please try again.', 'error')
            return redirect(url_for('chef_interface'))

@app.route('/update_report_item_status', methods=['POST'])
@login_required
@role_required(ROLES['manager'], ROLES['HQ'],)
def update_report_item_status():
    try:
        print("\n=== Updating Report Item Status ===")
        report_id = request.form.get('report_id')
        status = request.form.get('status')
        
        print(f"Received request - Report ID: {report_id}, Status: {status}")
        
        if not report_id or not status:
            print("Missing required parameters")
            return jsonify({'success': False, 'message': 'Missing required parameters'})
        
        # Get all reports
        reports_ref = db_ref.child('Reports')
        data = reports_ref.get()
        
        if not data:
            print("No reports found in database")
            return jsonify({'success': False, 'message': 'Report not found'})
            
        # Find the report and update its item status
        report_found = False
        if isinstance(data, dict):
            for key, report in data.items():
                if report.get('report_id') == report_id:
                    report_found = True
                    print(f"Found report with key: {key}")
                    
                    # Extract parent report ID from the report_id (e.g., N-005-01 -> N-005)
                    parent_report_id = report.get('parent_report_id')
                    if not parent_report_id and '-' in report_id:
                        parent_report_id = '-'.join(report_id.split('-')[:-1])
                    
                    # First, update the current item's status
                    update_data = {
                        'item_status': status,
                        'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'updated_by': session['user']['name']
                    }
                    reports_ref.child(key).update(update_data)
                    
                    if parent_report_id:
                        print(f"Processing parent report: {parent_report_id}")
                        
                        # Get all items in the parent report
                        items = []
                        for k, r in data.items():
                            if isinstance(r, dict):
                                current_parent_id = r.get('parent_report_id')
                                if not current_parent_id and '-' in r.get('report_id', ''):
                                    current_parent_id = '-'.join(r.get('report_id', '').split('-')[:-1])
                                if current_parent_id == parent_report_id:
                                    items.append(r)
                        
                        print(f"Found {len(items)} items in parent report")
                        
                        # Get updated statuses including the new status for current item
                        updated_items = []
                        for k, r in data.items():
                            if isinstance(r, dict):
                                current_parent_id = r.get('parent_report_id')
                                if not current_parent_id and '-' in r.get('report_id', ''):
                                    current_parent_id = '-'.join(r.get('report_id', '').split('-')[:-1])
                                if current_parent_id == parent_report_id:
                                    if r.get('report_id') == report_id:
                                        updated_items.append(status)  # Use the new status for current item
                                    else:
                                        updated_items.append(r.get('item_status', 'Pending'))
                        
                        print(f"Updated item statuses: {updated_items}")
                        
                        # Calculate overall report status
                        if all(s == 'Approved' for s in updated_items):
                            overall_status = 'Approved'
                        elif all(s == 'Rejected' for s in updated_items):
                            overall_status = 'Rejected'
                        elif any(s == 'Pending' for s in updated_items):
                            overall_status = 'Pending'
                        else:
                            overall_status = 'Accepted'
                        
                        print(f"Calculated overall status: {overall_status}")
                        
                        # Update status for all items in the report
                        for k, r in data.items():
                            if isinstance(r, dict):
                                current_parent_id = r.get('parent_report_id')
                                if not current_parent_id and '-' in r.get('report_id', ''):
                                    current_parent_id = '-'.join(r.get('report_id', '').split('-')[:-1])
                                if current_parent_id == parent_report_id:
                                    reports_ref.child(k).update({
                                        'status': overall_status,
                                        'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                                        'updated_by': session['user']['name']
                                    })
                    else:
                        # If no parent report, update both item status and report status
                        reports_ref.child(key).update({
                            'status': status,  # Set report status same as item status
                            'last_updated': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                            'updated_by': session['user']['name']
                        })
                    
                    print(f"Successfully updated report {report_id}")
                    return jsonify({'success': True})
        
        if not report_found:
            print(f"Report {report_id} not found")
            return jsonify({'success': False, 'message': 'Report not found'})
            
    except Exception as e:
        print(f"Error updating report item status: {str(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return jsonify({'success': False, 'message': str(e)})

@app.route('/update_report_status', methods=['POST'])
def handle_update_report():
    if request.method == 'POST':
        try:
            report_id = request.form.get('report_id')
            status = request.form.get('status')
            
            print(f"Received update request - Report ID: {report_id}, Status: {status}")  # Debug log
            
            if update_report_status(report_id, status):
                flash('Report status updated successfully', 'success')
            else:
                flash('Error updating report status', 'error')
                
            return redirect(url_for('reports_interface'))
        except Exception as e:
            print(f"Error in handle_update_report: {e}")  # Debug log
            flash(f'Error: {str(e)}', 'error')
            return redirect(url_for('reports_interface'))


# Save report to Firebase
def save_report(report_data, report_id):
    try:
        print("Attempting to save report:", report_data)
        reports_ref = db_ref.child('Reports')
        
        # Build the report entry
        report_entry = {
            'report_id': report_id,
            'parent_report_id': report_data.get('parent_report_id', ''),
            'sku': report_data.get('sku', ''),
            'item_name': report_data.get('item_name', ''),
            'report_type': report_data.get('report_type', ''),
            'quantity': report_data.get('quantity', ''),
            'unit': report_data.get('unit', ''),
            'date': report_data.get('date', ''),
            'chef_name': report_data.get('chef_name', ''),
            'status': report_data.get('status', 'Pending'),
            'branch': report_data.get('branch', ''),
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # Only add from_branch and to_branch if present (for transfer)
        if report_data.get('report_type') == 'transfer':
            report_entry['from_branch'] = report_data.get('from_branch', '')
            report_entry['to_branch'] = report_data.get('to_branch', '')

        # Push the new report to Firebase
        reports_ref.push(report_entry)
        return True
    except Exception as e:
        print(f"Detailed error in save_report: {str(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return False

# Update report status in Firebase
def update_report_status(report_id, new_status):
    try:
        print(f"Updating report {report_id} to status {new_status}")
        reports_ref = db_ref.child('Reports')
        data = reports_ref.get()
        
        if not data:
            print("No reports found in the database")
            return False

        # Find the report with matching report_id
        for key, value in data.items():
            if value.get('report_id') == report_id:
                # Update the status
                reports_ref.child(key).update({'status': new_status})
                print(f"Successfully updated status to {new_status} for Report ID {report_id}")
                return True

        print(f"Report ID {report_id} not found")
        return False
    except Exception as e:
        print(f"Error updating report status: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return False

# Get all reports from Firebase
def get_all_reports():
    try:
        reports_ref = db_ref.child('Reports')
        data = reports_ref.get()
        reports = []

        user_branch = session['user'].get('branch', None)
        is_manager = session['user']['role'] == ROLES['manager']

        if data:
            # Handle list format
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        if is_manager and item.get('branch', '') != user_branch:
                            continue  # Skip reports from other branches

                        reports.append({
                            'report_id': item.get('report_id', ''),
                            'sku': item.get('sku', ''),
                            'item_name': item.get('item_name', ''),
                            'report_type': item.get('report_type', ''),
                            'quantity': item.get('quantity', ''),
                            'unit': item.get('unit', ''),
                            'date': item.get('date', ''),
                            'chef_name': item.get('chef_name', ''),
                            'status': item.get('status', 'Pending'),
                            'branch': item.get('branch', '')
                        })
            # Handle dictionary format
            elif isinstance(data, dict):
                for key, value in data.items():
                    if isinstance(value, dict):
                        if is_manager and value.get('branch', '') != user_branch:
                            continue  # Skip reports from other branches

                        reports.append({
                            'report_id': value.get('report_id', ''),
                            'sku': value.get('sku', ''),
                            'item_name': value.get('item_name', ''),
                            'report_type': value.get('report_type', ''),
                            'quantity': value.get('quantity', ''),
                            'unit': value.get('unit', ''),
                            'date': value.get('date', ''),
                            'chef_name': value.get('chef_name', ''),
                            'status': value.get('status', 'Pending'),
                            'branch': value.get('branch', '')
                        })

        print(f"Retrieved {len(reports)} reports")
        return reports
    except Exception as e:
        print(f"Error getting reports: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return []

def initialize_reports_sheet():
    """Initialize reports collection in Firebase"""
    try:
        print("Initializing Reports collection...")
        reports_ref = db_ref.child('Reports')
        data = reports_ref.get()
        
        if not data:
            # Create default structure
            default_report = {
                'report_id': 'R-0001',
                'date': datetime.now().strftime('%Y-%m-%d'),
                'branch': 'Main',
                'sku': '',
                'item_name': '',
                'report_type': '',
                'quantity': 0,
                'unit': '',
                'chef_name': '',
                'status': 'Pending',
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            
            # Push the default report to Firebase
            reports_ref.push(default_report)
            print("Reports collection initialized with default structure")
            
        return True
    except Exception as e:
        print(f"Error initializing reports collection: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return False

@app.route('/report/<report_id>')
@login_required
@role_required(ROLES['HQ'],ROLES['developer'],ROLES['manager'])
def view_report_details(report_id):
    try:
        # Get all reports
        reports_ref = db_ref.child('Reports')
        data = reports_ref.get()
        
        if not data:
            flash('Report not found', 'error')
            return redirect(url_for('reports_interface'))
            
        # Find the specific report and its parent ID
        report = None
        parent_report_id = None
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and item.get('report_id') == report_id:
                    report = item
                    parent_report_id = item.get('parent_report_id')
                    if not parent_report_id and '-' in report_id:
                        parent_report_id = '-'.join(report_id.split('-')[:-1])
                    break
        elif isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, dict) and value.get('report_id') == report_id:
                    report = value
                    parent_report_id = value.get('parent_report_id')
                    if not parent_report_id and '-' in report_id:
                        parent_report_id = '-'.join(report_id.split('-')[:-1])
                    break
        
        if not report:
            flash('Report not found', 'error')
            return redirect(url_for('reports_interface'))
            
        # Check if user has access to this report
        if session['user']['role'] == 'manager' and report.get('branch') != session['user']['branch']:
            flash('You do not have permission to view this report', 'error')
            return redirect(url_for('reports_interface'))
            
        # Get all reports with the same parent ID
        related_reports = []
        if parent_report_id:
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict):
                        current_parent_id = item.get('parent_report_id')
                        if not current_parent_id and '-' in item.get('report_id', ''):
                            current_parent_id = '-'.join(item.get('report_id', '').split('-')[:-1])
                        if current_parent_id == parent_report_id:
                            related_reports.append(item)
            elif isinstance(data, dict):
                for key, value in data.items():
                    if isinstance(value, dict):
                        current_parent_id = value.get('parent_report_id')
                        if not current_parent_id and '-' in value.get('report_id', ''):
                            current_parent_id = '-'.join(value.get('report_id', '').split('-')[:-1])
                        if current_parent_id == parent_report_id:
                            related_reports.append(value)
            
            # Sort related reports by report_id to maintain order
            related_reports.sort(key=lambda x: x.get('report_id', ''))
            
        return render_template('report_details.html', 
                             report=report,
                             related_reports=related_reports,
                             parent_report_id=parent_report_id)
        
    except Exception as e:
        print(f"Error viewing report details: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        flash('Error loading report details', 'error')
        return redirect(url_for('reports_interface'))
