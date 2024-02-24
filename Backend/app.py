from flask import Flask, request, jsonify
import redis
import bcrypt
from uuid import uuid4

app = Flask(__name__)
r = redis.Redis(host='localhost', port=6379, db=0)

# Decorator để thêm các header CORS vào response
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS, PUT, DELETE'
    response.headers['Access-Control-Allow-Headers'] = 'Origin, Content-Type, Accept'
    return response

# Áp dụng decorator cho tất cả các route
@app.after_request
def after_request(response):
    response = add_cors_headers(response)
    return response

# Hash mật khẩu với bcrypt
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')

# Kiểm tra mật khẩu đã hash có khớp với mật khẩu nhập vào không
def check_password(hashed_password, password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))



@app.route('/user', methods=['POST'])
def create_user():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    role = data.get('role')

    # Kiểm tra xem username đã tồn tại hay chưa
    existing_user_key = f'user:{username}'
    if r.exists(existing_user_key):
        return jsonify({'error': 'Username already exists'}), 400

    # Tạo một ID tự sinh
    user_id = str(uuid4())

    # Hash mật khẩu trước khi lưu vào Redis
    hashed_password = hash_password(password)

    # Lưu thông tin người dùng vào Redis
    user_data = {
        'id': user_id,
        'username': username,
        'password': hashed_password,
        'role': role
    }
    user_key = f'user:{username}'  # Thay đổi key ở đây
    r.hmset(user_key, user_data)

    return jsonify({'message': 'User created successfully'})
#get  user
@app.route('/user', methods=['GET'])
def get_users():
    users = []
    for key in r.scan_iter('user:*'):
        data = r.hgetall(key)
        user = {}
        for field, value in data.items():
            if field == b'password':
                user[field.decode('utf-8')] = "*****"  # Ẩn mật khẩu
            else:
                user[field.decode('utf-8')] = value.decode('utf-8')
        users.append(user)
    return jsonify(users)
#get user by id
@app.route('/user/<user_id>', methods=['GET'])
def get_user_by_id(user_id):
    user_key = f'user:{user_id}'

    if r.exists(user_key):
        user_data = r.hgetall(user_key)
        user = {key.decode('utf-8'): value.decode('utf-8') for key, value in user_data.items()}
        return jsonify(user)
    else:
        return jsonify({'message': 'User not found'}), 404

#hàm thêm sản phẩm
@app.route('/product', methods=['POST'])
def create_product():
    data = request.json
    name = data.get('name')
    price = data.get('price')
    description = data.get('description')
    image_link = data.get('image_link')  # Thêm trường link ảnh
    category = data.get('category')  # Thêm trường nhóm sản phẩm
    manufacturer = data.get('manufacturer')  # Thêm trường nhà sản xuất
    year_of_manufacture = data.get('year_of_manufacture')  # Thêm trường năm sản xuất
    weight = data.get('weight')  # Thêm trường trọng lượng

    # Tạo một ID tự sinh cho sản phẩm
    product_id = str(uuid4())

    # Lưu thông tin sản phẩm vào Redis
    product_data = {
        'id': product_id,
        'name': name,
        'price': price,
        'description': description,
        'image_link': image_link,
        'category': category,
        'manufacturer': manufacturer,
        'year_of_manufacture': year_of_manufacture,
        'weight': weight
    }
    r.hmset(f'product:{product_id}', product_data)
    return jsonify({'message': 'Product created successfully'})

#Lấy thông tin sản phẩm


@app.route('/products', methods=['GET'])
def get_all_products():
    products = []
    for key in r.scan_iter('product:*'):
        data = r.hgetall(key)
        product = {}
        for field, value in data.items():
            product[field.decode('utf-8')] = value.decode('utf-8')
        products.append(product)
    return jsonify(products)


@app.route('/product/<product_id>', methods=['GET'])
def get_product_by_id(product_id):
    product_key = f'product:{product_id}'

    if r.exists(product_key):
        product_data = r.hgetall(product_key)
        product = {field.decode('utf-8'): value.decode('utf-8') for field, value in product_data.items()}
        return jsonify(product)
    else:
        return jsonify({'message': 'Product not found'}), 404

#xóa sp theo ID
@app.route('/product/<product_id>', methods=['DELETE'])
def delete_product(product_id):
    # Kiểm tra xem sản phẩm có tồn tại không
    if not r.exists(f'product:{product_id}'):
        return jsonify({'message': 'Product not found'}), 404
    
    # Xóa sản phẩm khỏi Redis
    r.delete(f'product:{product_id}')
    
    return jsonify({'message': f'Product with id {product_id} deleted successfully'})

#Phương thức sửa sp theo ID
@app.route('/product/<product_id>', methods=['PUT'])
def update_product(product_id):
    data = request.json

    # Kiểm tra xem sản phẩm có tồn tại trong Redis không
    if not r.exists(f'product:{product_id}'):
        return jsonify({'error': 'Product not found'}), 404

    # Cập nhật thông tin sản phẩm
    r.hmset(f'product:{product_id}', data)

    return jsonify({'message': 'Product updated successfully'})
from flask import g

# Hàm kiểm tra sự tồn tại của người dùng
def check_user(username):
    user_key = f'user:{username}'
    return r.exists(user_key)
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    # Kiểm tra xem người dùng có tồn tại trong Redis không
    if not check_user(username):
        return jsonify({'error': 'User not found'}), 404

    # Lấy thông tin người dùng từ Redis
    user_key = f'user:{username}'
    user_data = r.hgetall(user_key)
    stored_password = user_data.get(b'password').decode('utf-8')

    # Kiểm tra mật khẩu
    if not check_password(stored_password, password):
        return jsonify({'error': 'Invalid password'}), 401

    # Lấy vai trò của người dùng và lưu vào biến toàn cục
    g.user_role = user_data.get(b'role').decode('utf-8')

    return jsonify({'message': 'Login successful'})


# Phương thức DELETE để xóa hết dữ liệu đã test
@app.route('/clear_data', methods=['DELETE'])
def clear_data():
    r.flushdb()  # Xóa toàn bộ dữ liệu trong cơ sở dữ liệu Redis
    return jsonify({'message': 'All test data cleared successfully'})

if __name__ == '__main__':
    app.run(debug=True)