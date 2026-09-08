from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file, jsonify
from io import BytesIO
from functools import wraps
from flask_bcrypt import Bcrypt
import mysql.connector
import os
import requests
import time
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'
bcrypt = Bcrypt(app)

# Upload config
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024  # 5 MB
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'static', 'image', 'uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# --- FUNGSI KONEKSI DATABASE ---
def get_db_connection():
    return mysql.connector.connect(
        host='localhost',
        user='root',
        password='', 
        database='db_pengaduan_it',
        consume_results=True
    )

# Pastikan ada kategori default untuk foreign key complaint.id_category
def get_default_category_id():
    db = get_db_connection()
    cursor = db.cursor()
    try:
        cursor.execute('SELECT id_category FROM category ORDER BY id_category ASC LIMIT 1')
        row = cursor.fetchone()
        if row:
            return row[0]
        cursor.execute('INSERT INTO category (nama_category) VALUES (%s)', (1,))
        db.commit()
        return cursor.lastrowid
    finally:
        cursor.close()
        db.close()

# Decorator untuk proteksi halaman
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'loggedin' not in session:
            flash('Silakan login terlebih dahulu', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# --- ROUTE LOGIN ---
@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':

        username = request.form.get('username')
        password = request.form.get('password')

        db = get_db_connection()
        cursor = db.cursor(dictionary=True, buffered=True)

        try:
            cursor.execute(
                'SELECT * FROM users WHERE nama = %s',
                (username,)
            )

            user = cursor.fetchone()

            print("======================")
            print("USER :", user)

            if user:
                print("ROLE :", user['role'])
                print(
                    "PASSWORD COCOK :",
                    bcrypt.check_password_hash(
                        user['password'],
                        password
                    )
                )
            else:
                print("USER TIDAK DITEMUKAN")

            print("======================")

        finally:
            cursor.close()
            db.close()

        # ==============================
        # CEK LOGIN
        # ==============================

        if user and bcrypt.check_password_hash(
            user['password'],
            password
        ):

            session['loggedin'] = True
            session['id'] = user['id_user']
            session['username'] = user['nama']
            session['role'] = user.get(
                'role',
                'masyarakat'
            )

            flash(
                f'Selamat datang, {user["nama"]}!',
                'success'
            )

            # ==============================
            # REDIRECT BERDASARKAN ROLE
            # ==============================

            if session['role'] == 'admin':
                return redirect(
                    url_for('dashboard_admin')
                )

            elif session['role'] == 'petugas':
                return redirect(
                    url_for('dashboard_petugas')
                )

            elif session['role'] == 'masyarakat':
                return redirect(
                    url_for('dashboard')
                )

            else:
                session.clear()
                flash(
                    'Role pengguna tidak dikenali.',
                    'error'
                )
                return redirect(
                    url_for('login')
                )

        else:
            flash(
                'Username atau Password salah!',
                'error'
            )

    return render_template('login.html')

# --- ROUTE REGISTER (MENYIMPAN DATA) ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        nama = request.form.get('nama')
        nip = request.form.get('nip')
        hp = request.form.get('hp')
        password = request.form.get('password')
        setuju = request.form.get('setuju')

        if not setuju:
            flash('Anda harus menyetujui Syarat & Ketentuan!', 'error')
            return redirect(url_for('register'))

        if not nama or not password or not nip or not hp:
            flash('Semua kolom wajib diisi!', 'error')
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        db = get_db_connection()
        cursor = db.cursor()
        
        try:
            # Kolom di database Anda bernama 'password'
            cursor.execute('''
            INSERT INTO users (nama, password, nip, no_hp) 
            VALUES (%s, %s, %s, %s)
            ''', (nama, hashed_password, nip, hp))
            db.commit() 
            flash('Pendaftaran berhasil! Silakan login.', 'success')
            return redirect(url_for('login'))
            
        except mysql.connector.IntegrityError:
            flash('NIP atau Nomor HP sudah terdaftar!', 'error')
            return redirect(url_for('register'))
            
        finally:
            cursor.close()
            db.close()

    return render_template('register.html')


@app.route('/register-petugas', methods=['GET', 'POST'])
def register_petugas():
    if request.method == 'POST':
        nama = request.form.get('nama')
        nip = request.form.get('nip')
        hp = request.form.get('hp')
        password = request.form.get('password')
        setuju = request.form.get('setuju')

        if not setuju:
            flash('Anda harus menyetujui Syarat & Ketentuan!', 'error')
            return redirect(url_for('register_petugas'))

        if not nama or not password or not nip or not hp:
            flash('Semua kolom wajib diisi!', 'error')
            return redirect(url_for('register_petugas'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        db = get_db_connection()
        cursor = db.cursor()
        try:
            # Cek apakah kolom `role` ada di tabel users
            cursor.execute(
                "SELECT COUNT(*) FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = %s AND TABLE_NAME = %s AND COLUMN_NAME = %s",
                ('sipmas_db', 'users', 'role')
            )
            has_role = cursor.fetchone()[0] > 0

            if has_role:
                cursor.execute(
                    'INSERT INTO users (nama, password, nip, no_hp, role) VALUES (%s, %s, %s, %s, %s)',
                    (nama, hashed_password, nip, hp, 'petugas')
                )
            else:
                cursor.execute(
                    'INSERT INTO users (nama, password, nip, no_hp) VALUES (%s, %s, %s, %s)',
                    (nama, hashed_password, nip, hp)
                )
            db.commit()
            flash('Akun petugas berhasil dibuat. Silakan login.', 'success')
            return redirect(url_for('login'))

        except mysql.connector.IntegrityError:
            flash('NIP atau Nomor HP sudah terdaftar!', 'error')
            return redirect(url_for('register_petugas'))

        except Exception as e:
            db.rollback()
            flash(f'Gagal membuat akun petugas: {e}', 'error')
            return redirect(url_for('register_petugas'))

        finally:
            cursor.close()
            db.close()

    # Reuse the same register template; you can create a separate template later if needed
    return render_template('register.html')



# --- ROUTE DASHBOARD (MENAMPILKAN DATA DARI DB) ---
@app.route('/dashboard')
@login_required
def dashboard():
    try:
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)
        user_id = session['id']
        
        # Hitung statistik
        cursor.execute('SELECT COUNT(*) as total FROM complaint WHERE id_user = %s', (user_id,))
        total_complaint = cursor.fetchone()['total']
        
        cursor.execute('SELECT COUNT(*) as dalam_proses FROM complaint WHERE id_user = %s AND status = %s', (user_id, 'Sedang Diproses'))
        dalam_proses = cursor.fetchone()['dalam_proses']
        
        cursor.execute('SELECT COUNT(*) as selesai FROM complaint WHERE id_user = %s AND status = %s', (user_id, 'Selesai'))
        selesai = cursor.fetchone()['selesai']
        
        # Ambil data pengaduan terbaru
        cursor.execute('SELECT id_complaint, title, status, created_at FROM complaint WHERE id_user = %s ORDER BY created_at DESC LIMIT 5', (user_id,))
        pengaduan_list = cursor.fetchall()
        
        cursor.close()
        db.close()
        
        stats = {'total_complaint': total_complaint, 'dalam_proses': dalam_proses, 'selesai': selesai}
        return render_template('dashboard_user.html', stats=stats, pengaduan_list=pengaduan_list, user_nama=session.get('username'))
    except Exception as e:
        # Jika tabel belum dibuat, tampilkan pesan ini
        return f"<h2>Dashboard Error</h2><p>Pastikan tabel 'complaint' sudah dibuat di database. Error: {str(e)}</p>"

@app.route('/dashboard-petugas')
@login_required
def dashboard_petugas():

    if session.get('role') != 'petugas':
        flash('Akses ditolak. Hanya untuk petugas.', 'error')
        return redirect(url_for('dashboard'))

    db = None
    cursor = None

    try:
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)

        # ID PETUGAS YANG SEDANG LOGIN
        id_petugas = session.get('id')

        # =========================
        # STATISTIK PENGADUAN
        # =========================

        # Total pengaduan yang ditugaskan ke petugas ini
        cursor.execute('''
            SELECT COUNT(*) AS total
            FROM complaint
            WHERE assigned_to = %s
        ''', (id_petugas,))

        total_complaint = cursor.fetchone()['total']

        # Pending
        cursor.execute('''
            SELECT COUNT(*) AS pending
            FROM complaint
            WHERE assigned_to = %s
            AND status = %s
        ''', (id_petugas, 'pending'))

        pending = cursor.fetchone()['pending']

        # Sedang diproses
        cursor.execute('''
            SELECT COUNT(*) AS in_progress
            FROM complaint
            WHERE assigned_to = %s
            AND status = %s
        ''', (id_petugas, 'Sedang Diproses'))

        in_progress = cursor.fetchone()['in_progress']

        # Selesai
        cursor.execute('''
            SELECT COUNT(*) AS selesai
            FROM complaint
            WHERE assigned_to = %s
            AND status = %s
        ''', (id_petugas, 'Selesai'))

        selesai = cursor.fetchone()['selesai']

        # =========================
        # PENGADUAN TERBARU
        # =========================

        cursor.execute('''
            SELECT
                id_complaint AS id,
                title AS judul,
                status,
                created_at
            FROM complaint
            WHERE assigned_to = %s
            ORDER BY created_at DESC
            LIMIT 5
        ''', (id_petugas,))

        pengaduan_terbaru = cursor.fetchall()

        # =========================
        # DATA DASHBOARD
        # =========================

        stats = {
            'total_complaint': total_complaint,
            'pending': pending,
            'in_progress': in_progress,
            'selesai': selesai,
            'user_nama': session.get('username')
        }

        return render_template(
            'dashboard_petugas.html',
            stats=stats,
            pengaduan_terbaru=pengaduan_terbaru
        )

    except Exception as e:

        print('ERROR DASHBOARD PETUGAS:', e)

        return f'''
        <h2>Dashboard Petugas Error</h2>
        <p>{e}</p>
        '''

    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()

# =========================================================
# DASHBOARD ADMIN
# =========================================================

@app.route('/dashboard-admin')
@login_required
def dashboard_admin():

    # Hanya admin yang boleh masuk
    if session.get('role') != 'admin':
        flash('Akses ditolak. Halaman ini hanya untuk admin.', 'error')
        return redirect(url_for('dashboard'))

    db = None
    cursor = None

    try:
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)

        # ==============================
        # STATISTIK PENGADUAN
        # ==============================

        cursor.execute('''
            SELECT COUNT(*) AS total
            FROM complaint
        ''')
        total_complaint = cursor.fetchone()['total']

        cursor.execute('''
            SELECT COUNT(*) AS pending
            FROM complaint
            WHERE status = %s
        ''', ('pending',))
        pending = cursor.fetchone()['pending']

        cursor.execute('''
            SELECT COUNT(*) AS diproses
            FROM complaint
            WHERE status = %s
        ''', ('Sedang Diproses',))
        diproses = cursor.fetchone()['diproses']

        cursor.execute('''
            SELECT COUNT(*) AS selesai
            FROM complaint
            WHERE status = %s
        ''', ('Selesai',))
        selesai = cursor.fetchone()['selesai']

        # ==============================
        # JUMLAH USER
        # ==============================

        cursor.execute('''
            SELECT COUNT(*) AS total_user
            FROM users
            WHERE role = %s
        ''', ('masyarakat',))
        total_user = cursor.fetchone()['total_user']

        # ==============================
        # JUMLAH PETUGAS
        # ==============================

        cursor.execute('''
            SELECT COUNT(*) AS total_petugas
            FROM users
            WHERE role = %s
        ''', ('petugas',))
        total_petugas = cursor.fetchone()['total_petugas']

        # ==============================
        # PENGADUAN TERBARU
        # ==============================

        cursor.execute('''
            SELECT
                c.id_complaint AS id,
                c.title AS judul,
                c.status,
                c.created_at,
                u.nama AS pelapor
            FROM complaint c
            LEFT JOIN users u
                ON c.id_user = u.id_user
            ORDER BY c.created_at DESC
            LIMIT 5
        ''')

        pengaduan_terbaru = cursor.fetchall()

        # ==============================
        # DATA DASHBOARD
        # ==============================

        stats = {
            'total_complaint': total_complaint,
            'pending': pending,
            'diproses': diproses,
            'selesai': selesai,
            'total_user': total_user,
            'total_petugas': total_petugas,
            'user_nama': session.get('username')
        }

        return render_template(
            'dashboard_admin.html',
            stats=stats,
            pengaduan_terbaru=pengaduan_terbaru
        )

    except Exception as e:

        print('ERROR DASHBOARD ADMIN:', e)

        return f'''
        <h2>Dashboard Admin Error</h2>
        <p>{e}</p>
        '''

    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()   

# =========================================================
# DATA PENGADUAN - ADMIN
# =========================================================

@app.route('/admin/data-pengaduan')
@login_required
def data_pengaduan_admin():

    if session.get('role') != 'admin':
        flash('Akses ditolak. Halaman ini hanya untuk admin.', 'error')
        return redirect(url_for('dashboard'))

    db = None
    cursor = None

    try:
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)

        # Ambil semua pengaduan
        cursor.execute('''
            SELECT
                c.id_complaint AS id,
                c.title AS judul,
                c.deskripsi,
                c.lokasi,
                c.status,
                c.created_at,
                c.assigned_to,
                u.nama AS pelapor
            FROM complaint c
            LEFT JOIN users u
                ON c.id_user = u.id_user
            ORDER BY c.created_at DESC
        ''')

        pengaduan_list = cursor.fetchall()

        # Ambil semua user yang role-nya petugas
        cursor.execute('''
            SELECT id_user, nama
            FROM users
            WHERE role = 'petugas'
            ORDER BY nama ASC
        ''')

        petugas_list = cursor.fetchall()

        return render_template(
            'data_pengaduan_admin.html',
            pengaduan_list=pengaduan_list,
            petugas_list=petugas_list
        )

    except Exception as e:
        print('ERROR DATA PENGADUAN ADMIN:', e)
        return f'<h2>Error</h2><p>{e}</p>'

    finally:
        if cursor:
            cursor.close()

        if db:
            db.close()

@app.route('/admin/tugaskan-petugas/<int:id>', methods=['POST'])
@login_required
def tugaskan_petugas(id):

    if session.get('role') != 'admin':
        flash('Akses ditolak. Hanya untuk admin.', 'error')
        return redirect(url_for('dashboard'))

    petugas = request.form.get('petugas')

    if not petugas:
        flash('Silakan pilih petugas terlebih dahulu.', 'error')
        return redirect(url_for('data_pengaduan_admin'))

    db = None
    cursor = None

    try:
        db = get_db_connection()
        cursor = db.cursor()

        cursor.execute('''
            UPDATE complaint
            SET assigned_to = %s
            WHERE id_complaint = %s
        ''', (petugas, id))

        db.commit()

        flash('Pengaduan berhasil ditugaskan kepada petugas.', 'success')

    except Exception as e:

        if db:
            db.rollback()

        print('ERROR TUGASKAN PETUGAS:', e)

        flash('Gagal menugaskan pengaduan.', 'error')

    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()

    return redirect(url_for('data_pengaduan_admin'))

# =========================================================
# DATA USER - ADMIN
# =========================================================

@app.route('/admin/data-user')
@login_required
def data_user_admin():

    if session.get('role') != 'admin':
        flash('Akses ditolak. Halaman ini hanya untuk admin.', 'error')
        return redirect(url_for('dashboard'))

    db = None
    cursor = None

    try:
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)

        cursor.execute('''
            SELECT
                id_user,
                nama,
                nip,
                no_hp,
                role
            FROM users
            WHERE role = 'masyarakat'
            ORDER BY id_user DESC
        ''')

        user_list = cursor.fetchall()

        return render_template(
            'data_user_admin.html',
            user_list=user_list
        )

    except Exception as e:
        print('ERROR DATA USER ADMIN:', e)
        return f'<h2>Error</h2><p>{e}</p>'

    finally:
        if cursor:
            cursor.close()

        if db:
            db.close()


# =========================================================
# DATA PETUGAS - ADMIN
# =========================================================

@app.route('/admin/data-petugas')
@login_required
def data_petugas_admin():

    if session.get('role') != 'admin':
        flash('Akses ditolak. Halaman ini hanya untuk admin.', 'error')
        return redirect(url_for('dashboard'))

    db = None
    cursor = None

    try:
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)

        cursor.execute('''
            SELECT
                id_user,
                nama,
                nip,
                no_hp,
                role
            FROM users
            WHERE role = 'petugas'
            ORDER BY id_user DESC
        ''')

        petugas_list = cursor.fetchall()

        return render_template(
            'data_petugas_admin.html',
            petugas_list=petugas_list
        )

    except Exception as e:
        print('ERROR DATA PETUGAS ADMIN:', e)
        return f'<h2>Error</h2><p>{e}</p>'

    finally:
        if cursor:
            cursor.close()

        if db:
            db.close()   

@app.route('/admin/reset-password')
@login_required
def reset_password_admin():
    if session.get('role') != 'admin':
        flash('Anda tidak memiliki akses ke halaman ini.', 'danger')
        return redirect(url_for('login'))

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    cursor.execute('''
        SELECT id_user, nama, nip, no_hp, role
        FROM users
        WHERE role IN ('masyarakat', 'petugas')
        ORDER BY role ASC, nama ASC
    ''')

    user_list = cursor.fetchall()

    cursor.close()
    db.close()

    return render_template(
        'reset_password_admin.html',
        user_list=user_list
    )


@app.route('/admin/reset-password/<int:id>', methods=['POST'])
@login_required
def reset_password_user(id):
    if session.get('role') != 'admin':
        flash('Anda tidak memiliki akses ke halaman ini.', 'danger')
        return redirect(url_for('login'))

    password_baru = request.form.get('password_baru', '').strip()

    if not password_baru:
        flash('Password baru wajib diisi.', 'danger')
        return redirect(url_for('reset_password_admin'))

    if len(password_baru) < 6:
        flash('Password minimal 6 karakter.', 'danger')
        return redirect(url_for('reset_password_admin'))

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    # Pastikan yang diubah hanya User atau Petugas
    cursor.execute('''
        SELECT id_user, role
        FROM users
        WHERE id_user = %s
          AND role IN ('masyarakat', 'petugas')
    ''', (id,))

    user = cursor.fetchone()

    if not user:
        cursor.close()
        db.close()

        flash('User tidak ditemukan.', 'danger')
        return redirect(url_for('reset_password_admin'))

    password_hash = bcrypt.generate_password_hash(
        password_baru
    ).decode('utf-8')

    cursor.execute('''
        UPDATE users
        SET password = %s
        WHERE id_user = %s
    ''', (password_hash, id))

    db.commit()

    cursor.close()
    db.close()

    flash('Password berhasil direset.', 'success')

    return redirect(url_for('reset_password_admin'))

@app.route('/admin/lokasi')
@login_required
def data_lokasi_admin():
    if session.get('role') != 'admin':
        flash('Anda tidak memiliki akses ke halaman ini.', 'danger')
        return redirect(url_for('login'))

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    cursor.execute('''
        SELECT id_lokasi, nama_lokasi
        FROM lokasi
        ORDER BY id_lokasi DESC
    ''')

    lokasi_list = cursor.fetchall()

    cursor.close()
    db.close()

    return render_template(
        'lokasi_admin.html',
        lokasi_list=lokasi_list
    )


@app.route('/admin/lokasi/tambah', methods=['POST'])
@login_required
def tambah_lokasi_admin():
    if session.get('role') != 'admin':
        flash('Anda tidak memiliki akses ke halaman ini.', 'danger')
        return redirect(url_for('login'))

    nama_lokasi = request.form.get('nama_lokasi', '').strip()

    if not nama_lokasi:
        flash('Nama lokasi wajib diisi.', 'danger')
        return redirect(url_for('data_lokasi_admin'))

    db = get_db_connection()
    cursor = db.cursor()

    cursor.execute(
        'INSERT INTO lokasi (nama_lokasi) VALUES (%s)',
        (nama_lokasi,)
    )

    db.commit()
    cursor.close()
    db.close()

    flash('Lokasi berhasil ditambahkan.', 'success')
    return redirect(url_for('data_lokasi_admin'))


@app.route('/admin/lokasi/edit/<int:id>', methods=['POST'])
@login_required
def edit_lokasi_admin(id):
    if session.get('role') != 'admin':
        flash('Anda tidak memiliki akses ke halaman ini.', 'danger')
        return redirect(url_for('login'))

    nama_lokasi = request.form.get('nama_lokasi', '').strip()

    if not nama_lokasi:
        flash('Nama lokasi wajib diisi.', 'danger')
        return redirect(url_for('data_lokasi_admin'))

    db = get_db_connection()
    cursor = db.cursor()

    cursor.execute(
        '''
        UPDATE lokasi
        SET nama_lokasi = %s
        WHERE id_lokasi = %s
        ''',
        (nama_lokasi, id)
    )

    db.commit()
    cursor.close()
    db.close()

    flash('Lokasi berhasil diperbarui.', 'success')
    return redirect(url_for('data_lokasi_admin'))


@app.route('/admin/lokasi/hapus/<int:id>', methods=['POST'])
@login_required
def hapus_lokasi_admin(id):
    if session.get('role') != 'admin':
        flash('Anda tidak memiliki akses ke halaman ini.', 'danger')
        return redirect(url_for('login'))

    db = get_db_connection()
    cursor = db.cursor()

    cursor.execute(
        'DELETE FROM lokasi WHERE id_lokasi = %s',
        (id,)
    )

    db.commit()
    cursor.close()
    db.close()

    flash('Lokasi berhasil dihapus.', 'success')
    return redirect(url_for('data_lokasi_admin'))               

# ==========================================================
# VERIFIKASI LAPORAN UNTUK PETUGAS
# ==========================================================

@app.route('/verification-laporan')
@login_required
def verification_laporan_list():

    if session.get('role') != 'petugas':
        flash('Akses ditolak. Hanya untuk petugas.', 'error')
        return redirect(url_for('dashboard'))

    db = None
    cursor = None

    try:

        db = get_db_connection()
        cursor = db.cursor(dictionary=True)

        # ID petugas yang sedang login
        id_petugas = session.get('id')

        # Ambil pengaduan yang ditugaskan kepada petugas ini
        # dan masih pending
        cursor.execute('''
            SELECT
                c.id_complaint AS id,
                c.title,
                c.status,
                c.created_at,
                u.nama AS pelapor
            FROM complaint c
            LEFT JOIN users u
                ON c.id_user = u.id_user
            WHERE c.assigned_to = %s
            AND c.status = %s
            ORDER BY c.created_at DESC
        ''', (id_petugas, 'pending'))

        laporan_list = cursor.fetchall()

        return render_template(
            'verification_list.html',
            laporan_list=laporan_list
        )

    except Exception as e:

        print('ERROR VERIFICATION LIST:', e)

        return f'<h2>Error</h2><p>{e}</p>'

    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()


# ==========================================================
# DETAIL VERIFIKASI LAPORAN
# ==========================================================

@app.route('/verification-laporan/<int:id>', methods=['GET', 'POST'])
@login_required
def verification_laporan(id):

    if session.get('role') != 'petugas':
        flash('Akses ditolak. Hanya untuk petugas.', 'error')
        return redirect(url_for('dashboard'))

    db = None
    cursor = None

    try:

        db = get_db_connection()
        cursor = db.cursor(dictionary=True)

        # ID petugas yang sedang login
        id_petugas = session.get('id')


        # ==================================================
        # POST - UPDATE STATUS
        # ==================================================

        if request.method == 'POST':

            status_baru = request.form.get('status_baru')
            catatan = request.form.get('catatan_progress')

            # Pastikan pengaduan memang milik petugas ini
            cursor.execute('''
                UPDATE complaint
                SET
                    status = %s,
                    catatan_petugas = %s,
                    updated_at = NOW()
                WHERE id_complaint = %s
                AND assigned_to = %s
            ''', (
                status_baru,
                catatan,
                id,
                id_petugas
            ))

            db.commit()

            flash('Status laporan diperbarui.', 'success')

            return redirect(
                url_for('verification_laporan', id=id)
            )


        # ==================================================
        # GET - AMBIL DETAIL LAPORAN
        # ==================================================

        cursor.execute('''
            SELECT
                c.id_complaint AS id,
                c.title AS judul,
                c.deskripsi,
                c.lokasi,
                c.status,
                c.created_at,
                c.catatan_petugas,
                u.nama AS pelapor,
                u.no_hp,
                c.attachment,
                c.bukti_penyelesaian
            FROM complaint c
            LEFT JOIN users u
                ON c.id_user = u.id_user
            WHERE c.id_complaint = %s
            AND c.assigned_to = %s
        ''', (id, id_petugas))

        laporan = cursor.fetchone()


        if laporan:

            if laporan.get('attachment'):
                laporan['attachment'] = laporan['attachment'].replace(
                    '\\', '/'
                )

            if laporan.get('bukti_penyelesaian'):
                laporan['bukti_penyelesaian'] = laporan[
                    'bukti_penyelesaian'
                ].replace('\\', '/')


        if not laporan:

            flash(
                'Laporan tidak ditemukan atau bukan tugas Anda.',
                'error'
            )

            return redirect(
                url_for('verification_laporan_list')
            )


        return render_template(
            'verification_laporan.html',
            laporan=laporan
        )


    except Exception as e:

        if db:
            db.rollback()

        print('ERROR VERIFICATION LAPORAN:', e)

        return f'<h2>Error</h2><p>{e}</p>', 500


    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()



# ==========================================================
# DAFTAR PENGADUAN PETUGAS
# ==========================================================

@app.route('/daftar-pengaduan-petugas')
@login_required
def daftar_pengaduan_petugas():

    if session.get('role') != 'petugas':
        flash('Akses ditolak. Hanya untuk petugas.', 'error')
        return redirect(url_for('dashboard'))

    db = None
    cursor = None

    try:

        db = get_db_connection()
        cursor = db.cursor(dictionary=True)

        # ID petugas yang sedang login
        id_petugas = session.get('id')


        # Ambil hanya pengaduan milik petugas ini
        cursor.execute('''
            SELECT
                c.id_complaint AS id,
                c.title AS judul,
                c.status,
                c.created_at
            FROM complaint c
            WHERE c.assigned_to = %s
            ORDER BY c.created_at DESC
        ''', (id_petugas,))

        data = cursor.fetchall()


        return render_template(
            'daftar_pengaduan_petugas.html',
            pengaduan_list=data
        )


    except Exception as e:

        print('ERROR DAFTAR PENGADUAN PETUGAS:', e)

        return f'<h2>Error</h2><p>{e}</p>'


    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()



# ==========================================================
# DETAIL PENGADUAN PETUGAS
# ==========================================================

@app.route('/detail-pengaduan-petugas/<int:id>', methods=['GET', 'POST'])
@login_required
def detail_pengaduan_petugas(id):

    if session.get('role') != 'petugas':
        flash('Akses ditolak. Hanya untuk petugas.', 'error')
        return redirect(url_for('dashboard'))

    db = None
    cursor = None

    try:

        db = get_db_connection()
        cursor = db.cursor(dictionary=True)

        # ID petugas yang sedang login
        id_petugas = session.get('id')


        # Ambil detail hanya jika pengaduan ditugaskan
        # kepada petugas yang sedang login
        cursor.execute('''
            SELECT
                c.id_complaint AS id,
                c.title AS judul,
                c.deskripsi,
                c.lokasi,
                c.status,
                c.created_at,
                c.updated_at,
                c.catatan_petugas,
                c.prioritas,
                c.attachment,
                c.bukti_penyelesaian,
                u.nama AS nama_lengkap,
                u.no_hp
            FROM complaint c
            LEFT JOIN users u
                ON c.id_user = u.id_user
            WHERE c.id_complaint = %s
            AND c.assigned_to = %s
        ''', (id, id_petugas))

        pengaduan = cursor.fetchone()


        if pengaduan:

            if not pengaduan['prioritas']:
                pengaduan['prioritas'] = 'Sedang'


            if pengaduan.get('attachment'):
                pengaduan['attachment'] = pengaduan[
                    'attachment'
                ].replace('\\', '/')


            if pengaduan.get('bukti_penyelesaian'):
                pengaduan['bukti_penyelesaian'] = pengaduan[
                    'bukti_penyelesaian'
                ].replace('\\', '/')


        if not pengaduan:

            flash(
                'Pengaduan tidak ditemukan atau bukan tugas Anda.',
                'error'
            )

            return redirect(
                url_for('daftar_pengaduan_petugas')
            )


        return render_template(
            'detail_pengaduan_petugas.html',
            pengaduan=pengaduan
        )


    except Exception as e:

        print('ERROR DETAIL PENGADUAN PETUGAS:', e)

        return f'Terjadi kesalahan: {e}', 500


    finally:

        if cursor:
            cursor.close()

        if db:
            db.close()

@app.route('/update-status-pengaduan/<int:id>', methods=['POST'])
@login_required
def update_status_pengaduan(id):
    if session.get('role') != 'petugas':
        flash('Akses ditolak. Hanya untuk petugas.', 'error')
        return redirect(url_for('dashboard'))

    status = request.form.get('status') or request.form.get('status_baru')
    prioritas = request.form.get('prioritas') or request.form.get('priority')
    assigned_to = request.form.get('assigned_to')
    catatan = request.form.get('catatan_petugas') or request.form.get('catatan_progress')

    try:
        db = get_db_connection()
        cursor = db.cursor()
        # Build update parts dynamically
        updates = []
        params = []
        if status:
            updates.append('status = %s')
            params.append(status)
        if prioritas:
            updates.append('prioritas = %s')
            params.append(prioritas)
        if assigned_to:
            updates.append('assigned_to = %s')
            params.append(assigned_to)
        if catatan is not None:
            updates.append('catatan_petugas = %s')
            params.append(catatan)
        if updates:
            updates.append('updated_at = NOW()')
            sql = 'UPDATE complaint SET ' + ', '.join(updates) + ' WHERE id_complaint = %s'
            params.append(id)
            cursor.execute(sql, tuple(params))
            db.commit()
        cursor.close()
        db.close()
        flash('Perubahan status berhasil disimpan.', 'success')
    except Exception as e:
        print('Error update_status_pengaduan:', e)
        flash(f'Gagal menyimpan perubahan: {e}', 'error')

    return redirect(url_for('detail_pengaduan_petugas', id=id))


@app.route('/upload-bukti-penyelesaian/<int:id>', methods=['POST'])
@login_required
def upload_bukti_penyelesaian(id):
    if session.get('role') != 'petugas':
        flash('Akses ditolak. Hanya untuk petugas.', 'error')
        return redirect(url_for('dashboard'))

    uploaded_file = request.files.get('bukti_file')
    if not uploaded_file or uploaded_file.filename == '':
        flash('Tidak ada file yang diunggah.', 'error')
        return redirect(url_for('detail_pengaduan_petugas', id=id))

    # ensure bukti folder exists
    bukti_folder = os.path.join(app.root_path, 'static', 'uploads', 'bukti')
    os.makedirs(bukti_folder, exist_ok=True)

    try:
        filename = secure_filename(uploaded_file.filename)
        name, ext = os.path.splitext(filename)
        new_filename = f"bukti_{id}_{int(time.time())}{ext}"
        file_path = os.path.join(bukti_folder, new_filename)
        uploaded_file.save(file_path)

        # store filename in DB
        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute('UPDATE complaint SET bukti_penyelesaian = %s, status = %s, updated_at = NOW() WHERE id_complaint = %s', (new_filename, 'Selesai', id))
        db.commit()
        cursor.close()
        db.close()
        flash('Bukti berhasil diunggah dan status diubah menjadi Selesai.', 'success')
    except Exception as e:
        print('Error upload_bukti_penyelesaian:', e)
        flash(f'Gagal mengunggah bukti: {e}', 'error')

    return redirect(url_for('detail_pengaduan_petugas', id=id))

# --- ROUTE PENGADUAN SAYA ---
@app.route('/pengaduan-saya')
@login_required
def pengaduan_saya():
    try:
        search_query = request.args.get('q', '').strip()
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)

        if search_query:
            like_query = f"%{search_query}%"
            cursor.execute('''
                SELECT id_complaint, title, status, deskripsi, created_at
                FROM complaint
                WHERE id_user = %s AND (title LIKE %s OR deskripsi LIKE %s)
                ORDER BY created_at DESC
            ''', (session['id'], like_query, like_query))
        else:
            cursor.execute('SELECT id_complaint, title, status, deskripsi, created_at FROM complaint WHERE id_user = %s ORDER BY created_at DESC', (session['id'],))

        data_pengaduan = cursor.fetchall()
        cursor.close()
        db.close()
        return render_template('pengaduan_saya.html', pengaduan_list=data_pengaduan, search_query=search_query)
    except Exception as e:
        return f"<h2>Error</h2><p>{str(e)}</p>"

# --- ROUTE HAPUS PENGADUAN ---
@app.route('/pengaduan/hapus/<int:id>')
@login_required
def hapus_pengaduan(id):
    try:
        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute('DELETE FROM complaint WHERE id_complaint = %s AND id_user = %s', (id, session['id']))
        db.commit()
        cursor.close()
        db.close()
        flash('Pengaduan berhasil dihapus!', 'success')
    except Exception as e:
        flash(f'Gagal menghapus: {str(e)}', 'error')
    return redirect(url_for('pengaduan_saya'))

@app.route('/pengaduan/<int:id>')
@login_required
def detail_pengaduan(id):
    try:
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)
        cursor.execute('''
            SELECT c.id_complaint AS id, c.id_user, c.title AS judul, c.deskripsi, c.lokasi,
                   c.status, c.attachment, c.created_at, c.updated_at,
                   u.nama AS nama_lengkap, u.nama AS username, u.no_hp AS no_hp
            FROM complaint c
            JOIN users u ON c.id_user = u.id_user
            WHERE c.id_complaint = %s AND c.id_user = %s
        ''', (id, session['id']))
        pengaduan = cursor.fetchone()
        cursor.close()
        db.close()
        if not pengaduan:
            flash('Pengaduan tidak ditemukan atau bukan milik Anda.', 'error')
            return redirect(url_for('pengaduan_saya'))
        return render_template('detail_pengaduan.html', pengaduan=pengaduan)
    except Exception as e:
        print('Error loading detail_pengaduan:', e)
        flash('Terjadi kesalahan saat memuat detail pengaduan.', 'error')
        return redirect(url_for('pengaduan_saya'))

@app.route('/pengaduan/edit/<int:id>')
@login_required
def edit_pengaduan(id):
    flash('Fitur edit pengaduan sedang dalam pengembangan.', 'info')
    return redirect(url_for('pengaduan_saya'))
# --- ROUTE FORM PENGADUAN ---

@app.route('/form-pengaduan', methods=['GET', 'POST'])
@login_required
def form_pengaduan():

    # ==================================================
    # JIKA FORM DI-SUBMIT
    # ==================================================

    if request.method == 'POST':

        # ==============================
        # DATA PENGADUAN
        # ==============================

        judul = request.form.get('title')
        deskripsi = request.form.get('deskripsi')


        # ==============================
        # DATA LOKASI
        # ==============================

        lokasi = request.form.get('lokasi')
        alamat_detail = request.form.get('alamat_detail')


        # Gabungkan lokasi dengan alamat detail
        if alamat_detail:
            lokasi = f"{lokasi} - {alamat_detail}"


        # ==============================
        # FILE HANDLING
        # ==============================

        uploaded_file = request.files.get('file')
        saved_filename = ''


        db = get_db_connection()
        cursor = db.cursor()


        try:

            # ==============================
            # KATEGORI DEFAULT
            # ==============================

            category_id = get_default_category_id()


            # ==============================
            # SIMPAN PENGADUAN
            # ==============================

            cursor.execute('''
                INSERT INTO complaint
                (
                    id_user,
                    title,
                    deskripsi,
                    lokasi,
                    status,
                    attachment,
                    id_category
                )
                VALUES
                (
                    %s,
                    %s,
                    %s,
                    %s,
                    'pending',
                    %s,
                    %s
                )
            ''', (
                session['id'],
                judul,
                deskripsi,
                lokasi,
                saved_filename,
                category_id
            ))


            db.commit()


            inserted_id = cursor.lastrowid


            # ==============================
            # SIMPAN FILE
            # ==============================

            if uploaded_file and uploaded_file.filename:

                filename = secure_filename(
                    uploaded_file.filename
                )


                name, ext = os.path.splitext(filename)


                new_filename = (
                    f"{inserted_id}_"
                    f"{int(time.time())}"
                    f"{ext}"
                )


                file_path = os.path.join(
                    app.config['UPLOAD_FOLDER'],
                    new_filename
                )


                uploaded_file.save(file_path)


                saved_filename = (
                    f"image/uploads/{new_filename}"
                )


                # ==============================
                # UPDATE ATTACHMENT
                # ==============================

                cursor.execute(
                    '''
                    UPDATE complaint
                    SET attachment = %s
                    WHERE id_complaint = %s
                    ''',
                    (
                        saved_filename,
                        inserted_id
                    )
                )


                db.commit()


            flash(
                'Pengaduan berhasil dikirim!',
                'success'
            )


            return redirect(
                url_for('pengaduan_saya')
            )


        except Exception as e:

            db.rollback()


            print(
                'Error inserting pengaduan:',
                e
            )


            flash(
                f'Gagal mengirim pengaduan: {e}',
                'error'
            )


            return redirect(
                url_for('form_pengaduan')
            )


        finally:

            cursor.close()
            db.close()


    # ==================================================
    # AMBIL DATA LOKASI DARI DATABASE
    # ==================================================

    db = get_db_connection()

    cursor = db.cursor(dictionary=True)


    try:

        cursor.execute('''
            SELECT
                id_lokasi,
                nama_lokasi
            FROM lokasi
            ORDER BY id_lokasi ASC
        ''')


        lokasi = cursor.fetchall()


    finally:

        cursor.close()
        db.close()


    # ==================================================
    # TAMPILKAN FORM
    # ==================================================

    return render_template(
        'form_pengaduan.html',
        lokasi=lokasi
    )


# --- ROUTE TAMBAHAN (Fix Error Sebelumnya) ---
@app.route('/logout')
def logout():
    session.clear()
    flash('Anda telah logout.', 'info')
    return redirect(url_for('login'))

@app.route('/riwayat')
@login_required
def riwayat():
    db = None
    cursor = None

    try:
        db = get_db_connection()
        cursor = db.cursor(dictionary=True)

        user_id = session['id']

        # Ambil data pengaduan
        cursor.execute('''
            SELECT 
                id_complaint AS id,
                title AS judul,
                deskripsi,
                status,
                created_at,
                updated_at
            FROM complaint
            WHERE id_user = %s
            ORDER BY created_at DESC
        ''', (user_id,))

        riwayat_data = cursor.fetchall()

        # Total pengaduan
        cursor.execute('''
            SELECT COUNT(*) AS total
            FROM complaint
            WHERE id_user = %s
        ''', (user_id,))

        total_complaint = cursor.fetchone()['total']

        # Pengaduan selesai
        cursor.execute('''
            SELECT COUNT(*) AS selesai
            FROM complaint
            WHERE id_user = %s
            AND status = %s
        ''', (user_id, 'Selesai'))

        selesai_count = cursor.fetchone()['selesai']

        # Pengaduan belum selesai
        cursor.execute('''
            SELECT COUNT(*) AS belum_selesai
            FROM complaint
            WHERE id_user = %s
            AND status != %s
        ''', (user_id, 'Selesai'))

        belum_selesai_count = cursor.fetchone()['belum_selesai']

        stats = {
            'total': total_complaint,
            'selesai': selesai_count,
            'belum_selesai': belum_selesai_count,
            'avg_time': '20:5'
        }

        return render_template(
            'riwayat.html',
            riwayat_list=riwayat_data,
            stats=stats
        )

    except Exception as e:
        print(f'Error pada fungsi riwayat: {e}')
        return f'Terjadi kesalahan sistem: {e}', 500

    finally:
        if cursor:
            cursor.close()

        if db:
            db.close()


# =========================================================
# EXPORT RIWAYAT KE EXCEL
# =========================================================

@app.route('/riwayat/export-excel')
@login_required
def export_riwayat_excel():
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font, Alignment
        from flask import send_file
        from io import BytesIO

        db = get_db_connection()
        cursor = db.cursor(dictionary=True)

        cursor.execute('''
            SELECT
                id_complaint AS id,
                title AS judul,
                deskripsi,
                status,
                created_at,
                updated_at
            FROM complaint
            WHERE id_user = %s
            ORDER BY created_at DESC
        ''', (session['id'],))

        data = cursor.fetchall()

        cursor.close()
        db.close()

        workbook = Workbook()
        sheet = workbook.active
        sheet.title = 'Riwayat Pengaduan'

        # Header
        headers = [
            'No',
            'ID Tiket',
            'Judul Pengaduan',
            'Deskripsi',
            'Status',
            'Tanggal Dibuat',
            'Tanggal Diperbarui'
        ]

        for col, header in enumerate(headers, start=1):
            cell = sheet.cell(row=1, column=col, value=header)
            cell.font =  Font(bold=True)
            cell.alignment = Alignment(horizontal='center')

        # Data
        for nomor, item in enumerate(data, start=1):

            ticket_id = f"TIK-{int(item['id']):04d}"

            sheet.cell(row=nomor + 1, column=1, value=nomor)
            sheet.cell(row=nomor + 1, column=2, value=ticket_id)
            sheet.cell(row=nomor + 1, column=3, value=item['judul'])
            sheet.cell(row=nomor + 1, column=4, value=item['deskripsi'])
            sheet.cell(row=nomor + 1, column=5, value=item['status'])
            sheet.cell(row=nomor + 1, column=6, value=str(item['created_at']))
            sheet.cell(row=nomor + 1, column=7, value=str(item['updated_at']))

        # Lebar kolom
        sheet.column_dimensions['A'].width = 8
        sheet.column_dimensions['B'].width = 15
        sheet.column_dimensions['C'].width = 35
        sheet.column_dimensions['D'].width = 50
        sheet.column_dimensions['E'].width = 20
        sheet.column_dimensions['F'].width = 25
        sheet.column_dimensions['G'].width = 25

        # Simpan ke memory
        output = BytesIO()
        workbook.save(output)
        output.seek(0)

        return send_file(
            output,
            as_attachment=True,
            download_name='riwayat_pengaduan.xlsx',
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        )

    except Exception as e:
        print(f'Error export Excel: {e}')
        flash(f'Gagal export Excel: {e}', 'error')
        return redirect(url_for('riwayat'))


# =========================================================
# DOWNLOAD PDF PER PENGADUAN
# =========================================================

@app.route('/riwayat/pdf/<int:id>')
@login_required
def download_riwayat_pdf(id):

    try: 
        from   eportlab.lib.pagesizes import A4
        from   eportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
        from   reportlab.lib.styles import getSampleStyleSheet
        from   reportlab.lib.units import cm
        from flask import send_file
        from io import BytesIO

        db = get_db_connection()
        cursor = db.cursor(dictionary=True)

        cursor.execute('''
            SELECT
                c.id_complaint AS id,
                c.title AS judul,
                c.deskripsi,
                c.lokasi,
                c.status,
                c.created_at,
                c.updated_at,
                u.nama AS nama_lengkap,
                u.no_hp
            FROM complaint c
            LEFT JOIN users u
                ON c.id_user = u.id_user
            WHERE c.id_complaint = %s
            AND c.id_user = %s
        ''', (id, session['id']))

        pengaduan = cursor.fetchone()

        cursor.close()
        db.close()

        if not pengaduan:
            flash('Pengaduan tidak ditemukan.', 'error')
            return redirect(url_for('riwayat'))

        output = BytesIO()

        doc = SimpleDocTemplate(
            output,
            pagesize=A4,
            rightMargin=2 * cm,
            leftMargin=2 * cm,
            topMargin=2 * cm,
            bottomMargin=2 * cm
        )

        styles = getSampleStyleSheet()

        isi = []

        ticket_id = f"TIK-{int(pengaduan['id']):04d}"

        isi.append(
            Paragraph(
                'LAPORAN PENGADUAN IT',
                styles['Title']
            )
        )

        isi.append(Spacer(1, 20))

        isi.append(
            Paragraph(
                f'<b>ID Tiket:</b> {ticket_id}',
                styles['Normal']
            )
        )

        isi.append(Spacer(1, 10))

        isi.append(
            Paragraph(
                f'<b>Nama Pelapor:</b> {pengaduan["nama_lengkap"] or "-"}',
                styles['Normal']
            )
        )

        isi.append(Spacer(1, 10))

        isi.append(
            Paragraph(
                f'<b>No. HP:</b> {pengaduan["no_hp"] or "-"}',
                styles['Normal']
            )
        )

        isi.append(Spacer(1, 10))

        isi.append(
            Paragraph(
                f'<b>Judul:</b> {pengaduan["judul"] or "-"}',
                styles['Normal']
            )
        )

        isi.append(Spacer(1, 10))

        isi.append(
            Paragraph(
                f'<b>Lokasi:</b> {pengaduan["lokasi"] or "-"}',
                styles['Normal']
            )
        )

        isi.append(Spacer(1, 10))

        isi.append(
            Paragraph(
                f'<b>Status:</b> {pengaduan["status"] or "-"}',
                styles['Normal']
            )
        )

        isi.append(Spacer(1, 10))

        isi.append(
            Paragraph(
                f'<b>Tanggal Pengaduan:</b> {pengaduan["created_at"] or "-"}',
                styles['Normal']
            )
        )

        isi.append(Spacer(1, 20))

        isi.append(
            Paragraph(
                '<b>Deskripsi Pengaduan:</b>',
                styles['Heading3']
            )
        )

        isi.append(Spacer(1, 8))

        deskripsi = pengaduan['deskripsi'] or '-'

        isi.append(
            Paragraph(
                deskripsi,
                styles['BodyText']
            )
        )

        doc.build(isi)

        output.seek(0)

        return send_file(
            output,
            as_attachment=True,
            download_name=f'{ticket_id}.pdf',
            mimetype='application/pdf'
        )

    except Exception as e:
        print(f'Error download PDF: {e}')
        flash(f'Gagal membuat PDF: {e}', 'error')
        return redirect(url_for('riwayat'))

    except Exception as e:
        # Menangkap error jika ada masalah query atau database
        print(f"Error pada fungsi riwayat: {e}")
        return f"Terjadi kesalahan sistem: {e}", 500

    finally:
        # Menutup database dengan aman, baik sukses maupun error
        if db:
            cursor.close()
            db.close()
            


if __name__ == '__main__':
    app.run(debug=True)