import sqlite3
from flask import Flask, jsonify, request, url_for, render_template

app = Flask(__name__)

@app.route('/')
def index(): 
    """API base URL"""
    return ('<h1> Final results </h1>')

# SQLite database file path
DATABASE = 'nvd_cve.db'

# Function to connect to SQLite database
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

# Function to get a single row from database (for CVE and product)
def query_db(query, args=(), one=False):
    cur = get_db_connection().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv

@app.route('/help', methods=['GET'])
def routes_info():
    """Print all defined routes and their endpoint docstrings."""
    routes = []
    for rule in app.url_map.iter_rules():
        try:
            if rule.endpoint != 'static':
                if hasattr(app.view_functions[rule.endpoint], 'import_name'):
                    import_name = app.view_functions[rule.endpoint].import_name
                    obj = import_string(import_name)
                    routes.append({rule.rule: "%s\n%s" % (",".join(list(rule.methods)), obj.__doc__)})
                else:
                    routes.append({rule.rule: app.view_functions[rule.endpoint].__doc__})
        except Exception as exc:
            routes.append({rule.rule: 
                           "(%s) INVALID ROUTE DEFINITION!!!" % rule.endpoint})
            route_info = "%s => %s" % (rule.rule, rule.endpoint)
            app.logger.error("Invalid route: %s" % route_info, exc_info=True)
            # func_list[rule.rule] = obj.__doc__

    return jsonify(code=200, data=routes)

# Route to get severity distribution
@app.route('/severity/dist', methods=['GET'])
def get_severity_count():
    """Base severity distribution."""
    sql = 'select base_severity,count(id) n_cve from cve group by 1 order by 2;'
    query_result = query_db(sql)
    return jsonify({'severity_distribution': [{dict(row)['base_severity']: dict(row)['n_cve']} for row in query_result]})
# Extra: how severity has changed
@app.route('/severity/year', methods=['GET'])
def get_severity_year():
    """Base severity change over time"""
    sql =   '''
            select strftime('%Y', published) year,round(avg(case when base_severity = 'LOW' then 0.00
                                                        when base_severity = 'MEDIUM' then 1.00
                                                        when base_severity = 'HIGH' then 2.00
                                                        when base_severity = 'CRITICAL' then 3.00
                                                end),2) avg_base_severity,count(id) n_cve from cve group by 1 order by 1;
            '''
    query_result = query_db(sql)
    return jsonify({'severity_distribution': [dict(row) for row in query_result]})

# Route to get worst products or platforms
@app.route('/worst_products_platforms/<string:prod_or_plat>', methods=['GET'])
def get_worst(prod_or_plat):
    """Get top 10 worst products/platforms. Variable prod_or_plat = [product,platform]"""
    if prod_or_plat not in ['product','platform']:
        return {'error': 'prod_or_plat not in [product,platform]'}
    if prod_or_plat == 'product':
        sql =   '''
                    select vendor,
                            product,
                            count(cve_id) n_cve 
                    from cve_product  
                    where not negate and vulnerable
                    group by 1,2 
                    order by 3 desc 
                limit 10;
                '''
        query_result = query_db(sql)
    if prod_or_plat == 'platform':
    
        sql =   '''
                    select vendor,
                        count(cve_id) n_cve 
                    from cve_product  
                    where not negate and vulnerable
                    group by 1
                    order by 2 desc 
                    limit 10;
                '''
        query_result = query_db(sql)
    return jsonify({'type':prod_or_plat,'result':[dict(row) for row in query_result]})

# Route to get top 10 vulnerabilities that have the highest impact or highest exploitability scores
@app.route('/top_vul/<int:cvss_ver>/<string:score>', methods=['GET'])
def get_ver_impact(cvss_ver,score):
    """Get top 10 vulnerabilities based on the score and cvss version. cvss_ver = [2,3] & score = [impact_score,exploitability_score]"""
    if cvss_ver not in [2,3]:
        return {'error': 'cvss_ver needs to be 2 or 3'}
    else:
        if score not in ['impact_score','exploitability_score']:
            return {'error': 'score needs to be impact_score or exploitability_score'}
        else:
            query_result = query_db(f'''
                                    select case when {cvss_ver} = 2 then vector_string_v2 else vector_string_v3 end vector_string
                                        ,sum({score}) sum_score
                                        ,round(avg({score}*1.0),1) avg_score
                                        ,count(id) n_cve
                                    from cve 
                                    where cvss_ver = {cvss_ver}
                                    group by 1 
                                    order by 2 desc, 4 desc
                                    limit 10;
                                    ''')
            
            return jsonify({'cvss_ver':cvss_ver,
                            'score_type':score,
                            'result':[dict(row) for row in query_result]})
        

# Route to get a specific vulnerability by CVE or product ID
@app.route('/cve_or_prod/<string:cve_or_prod>/<string:id>', methods=['GET'])
def get_info(cve_or_prod,id):
    """Possibility to query information about either CSV (https://nvd.nist.gov/vuln/search) or product ID (https://nvd.nist.gov/products/cpe/search)"""
    if cve_or_prod not in ['cve','product']:
        return {'error': 'cve_or_prod needs to be cve or product'}
    else:
        source_db = {'cve':{'source':'cve',
                            'id_col':'cve'},
                     'product':{'source':'cve_product',
                                'id_col':'criteria'}}
        sql = f'''SELECT * FROM {source_db[cve_or_prod]['source']} WHERE {source_db[cve_or_prod]['id_col']} = '{id}';'''

        query_result = query_db(sql)
        return jsonify({'type':cve_or_prod,
                        'result':[dict(row) for row in query_result]})

# Run the Flask application
if __name__ == '__main__':
    app.run(debug=False)