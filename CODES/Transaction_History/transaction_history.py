#transaction histroy codes
"""
@app.route('/transaction_history')
@login_required
@role_required(ROLES['manager'], ROLES['accountant'], ROLES['HQ'],ROLES['developer'])
def transaction_history():
    try:
        inventory_data = load_inventory_data()
        return render_template('transaction_history.html', 
                             inventory=inventory_data)
    except Exception as e:
        print(f"Error in transaction history: {e}")
        flash('Error loading transaction history', 'error')
        return redirect(url_for('index'))

def get_product_invoices(isbn, start_date=None, end_date=None):
    """Get all invoices containing the specified product"""
    try:
        invoices = get_all_invoices()
        product_invoices = []

        for invoice in invoices:
            # Skip refused invoices
            if invoice.get('status') == 'Refused':
                continue
                
            for item in invoice.get('items', []):
                if item.get('product') == isbn:
                    # Determine if this is a purchase or sale based on document type
                    transaction_type = 'purchase' if invoice.get('document_type') in ['ريسيبت', 'فاتورة', 'طلب استلام','Other'] else 'Unknown'
                    
                    invoice_data = {
                        'type': transaction_type,
                        'transaction_id': invoice.get('invoice_number'),
                        'date': invoice.get('date'),
                        'quantity': item.get('quantity'),
                        'unit_price': item.get('price'),
                        'total_amount': item.get('total'),
                        'unit': item.get('unit'),
                        'branch': invoice.get('branch'),
                        'status': invoice.get('status'),
                        'created_by': invoice.get('created_by'),
                        'vendor_name': invoice.get('vendor_name', ''),
                        'document_type': invoice.get('document_type', ''),
                        'last_updated': invoice.get('review_date'),
                        'updated_by': invoice.get('reviewed_by'),
                        'timestamp': invoice.get('created_at')
                    }
                    if should_include_transaction(invoice_data, start_date, end_date):
                        product_invoices.append(invoice_data)

        return product_invoices
    except Exception as e:
        print(f"Error getting product invoices: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return []

def get_product_creation(isbn, start_date=None, end_date=None):
    """Get all creation reports for the specified product"""
    try:
        reports = get_all_reports()
        creation_reports = []

        for report in reports:
            if (report.get('report_type') == 'creation' and 
                report.get('sku') == isbn):
                report_data = {
                    'type': 'creation',
                    'transaction_id': report.get('report_id'),
                    'parent_id': report.get('parent_report_id'),
                    'date': report.get('date'),
                    'quantity': report.get('quantity'),
                    'unit': report.get('unit'),
                    'branch': report.get('branch'),
                    'status': report.get('item_status') or report.get('status'),
                    'created_by': report.get('chef_name'),
                    'last_updated': report.get('last_updated'),
                    'updated_by': report.get('updated_by'),
                    'item_name': report.get('item_name'),
                    'timestamp': report.get('timestamp')
                }
                if should_include_transaction(report_data, start_date, end_date):
                    creation_reports.append(report_data)

        return creation_reports
    except Exception as e:
        print(f"Error getting product creation reports: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return []

def get_product_wastage(isbn, start_date=None, end_date=None):
    """Get all wastage reports for the specified product"""
    try:
        reports = get_all_reports()
        wastage_reports = []

        for report in reports:
            if (report.get('report_type') == 'waste' and 
                report.get('sku') == isbn):
                report_data = {
                    'type': 'wastage',
                    'transaction_id': report.get('report_id'),
                    'parent_id': report.get('parent_report_id'),
                    'date': report.get('date'),
                    'quantity': report.get('quantity'),
                    'unit': report.get('unit'),
                    'branch': report.get('branch'),
                    'status': report.get('item_status') or report.get('status'),
                    'created_by': report.get('chef_name'),
                    'last_updated': report.get('last_updated'),
                    'updated_by': report.get('updated_by'),
                    'item_name': report.get('item_name'),
                    'timestamp': report.get('timestamp')
                }
                if should_include_transaction(report_data, start_date, end_date):
                    wastage_reports.append(report_data)

        return wastage_reports
    except Exception as e:
        print(f"Error getting product wastage: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return []

@app.route('/get_product_transactions')
@login_required
def get_product_transactions():
    try:
        product_isbn = request.args.get('isbn')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        transaction_type = request.args.get('type')

        if not product_isbn:
            return jsonify({'success': False, 'message': 'Product ISBN is required'})

        print(f"\nGetting transactions for product {product_isbn}")
        print(f"Date range: {start_date} to {end_date}")
        print(f"Transaction type: {transaction_type}")

        # Get all types of transactions
        invoices = get_product_invoices(product_isbn, start_date, end_date)
        wastage = get_product_wastage(product_isbn, start_date, end_date)
        transfers = get_product_transfers(product_isbn, start_date, end_date)
        creations = get_product_creation(product_isbn, start_date, end_date)

        # Filter by transaction type if specified
        transactions = []
        if not transaction_type or transaction_type == 'all':
            transactions = invoices + wastage + transfers + creations
        elif transaction_type == 'purchase':
            transactions = [t for t in invoices if t['type'] == 'purchase']
        elif transaction_type == 'wastage':
            transactions = wastage
        elif transaction_type == 'transfer':
            transactions = transfers
        elif transaction_type == 'creation':
            transactions = creations

        # Sort transactions by date (newest first)
        transactions.sort(key=lambda x: x.get('date', ''), reverse=True)

        return jsonify({
            'success': True,
            'transactions': transactions
        })

    except Exception as e:
        print(f"Error getting product transactions: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return jsonify({'success': False, 'message': str(e)})

def get_product_transfers(isbn, start_date=None, end_date=None):
    """Get all transfer reports for the specified product"""
    try:
        reports = get_all_reports()
        transfer_reports = []

        for report in reports:
            if (report.get('report_type') == 'transfer' and 
                report.get('sku') == isbn):
                # Skip rejected transfers
                if report.get('item_status') == 'Rejected' or report.get('status') == 'Rejected':
                    continue
                    
                report_data = {
                    'type': 'transfer',
                    'transaction_id': report.get('report_id'),
                    'parent_id': report.get('parent_report_id'),
                    'date': report.get('date'),
                    'quantity': report.get('quantity'),
                    'unit': report.get('unit'),
                    'item_name': report.get('item_name'),
                    'from_branch': report.get('from_branch'),
                    'to_branch': report.get('to_branch'),
                    'branch': report.get('branch'),  # Current branch
                    'status': report.get('item_status') or report.get('status'),  # Use item_status first
                    'created_by': report.get('chef_name'),
                    'timestamp': report.get('timestamp'),
                    'updated_by': report.get('updated_by'),
                    'last_updated': report.get('last_updated')
                }
                if should_include_transaction(report_data, start_date, end_date):
                    transfer_reports.append(report_data)

        return transfer_reports
    except Exception as e:
        print(f"Error getting product transfers: {e}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        return []

def should_include_transaction(transaction, start_date, end_date):
    """Helper function to check if a transaction falls within the date range"""
    if not start_date and not end_date:
        return True

    try:
        transaction_date = datetime.strptime(transaction.get('date'), '%Y-%m-%d')
        
        if start_date:
            start = datetime.strptime(start_date, '%Y-%m-%d')
            if transaction_date < start:
                return False
                
        if end_date:
            end = datetime.strptime(end_date, '%Y-%m-%d')
            if transaction_date > end:
                return False
                
        return True
    except Exception:
        return True
"""
