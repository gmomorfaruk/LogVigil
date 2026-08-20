import os
import sys
import time
import secrets
import threading
import sqlite3
import resource
import gc

# Add backend directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../backend')))

import db
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Configuration
TEST_FILE_SIZE_MB = 50
LARGE_FILE_SIZE_MB = 1100  # 1.1 GB
DB_THREADS = 10
QUERIES_PER_THREAD = 100
STREAM_CHUNK_SIZE = 64 * 1024 * 1024  # 64 MB chunk stream buffer

def get_max_memory_mb():
    """Returns max resident memory consumption in MB."""
    usage = resource.getrusage(resource.RUSAGE_SELF)
    return usage.ru_maxrss / 1024.0

def benchmark_crypto():
    print(f"[*] Starting Cryptographic Benchmarks (Payload size: {TEST_FILE_SIZE_MB} MB)...")
    
    pin = "12345678"
    salt = os.urandom(16)
    
    start_kdf = time.perf_counter()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    key = kdf.derive(pin.encode('utf-8'))
    kdf_time = time.perf_counter() - start_kdf
    print(f"  [+] PBKDF2 Key Derivation: {kdf_time:.4f} seconds")
    
    plaintext = secrets.token_bytes(TEST_FILE_SIZE_MB * 1024 * 1024)
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key)
    
    start_enc = time.perf_counter()
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    enc_time = time.perf_counter() - start_enc
    enc_throughput = TEST_FILE_SIZE_MB / enc_time
    print(f"  [+] AES-256-GCM Encryption: {enc_time:.4f} seconds ({enc_throughput:.2f} MB/s)")
    
    start_dec = time.perf_counter()
    decrypted = aesgcm.decrypt(nonce, ciphertext, None)
    dec_time = time.perf_counter() - start_dec
    dec_throughput = TEST_FILE_SIZE_MB / dec_time
    print(f"  [+] AES-256-GCM Decryption: {dec_time:.4f} seconds ({dec_throughput:.2f} MB/s)")
    
    assert decrypted == plaintext
    
    return {
        "kdf_time_s": kdf_time,
        "enc_time_s": enc_time,
        "enc_throughput_mbs": enc_throughput,
        "dec_time_s": dec_time,
        "dec_throughput_mbs": dec_throughput
    }

def stream_encrypt_file(input_path: str, output_path: str, key: bytes):
    """
    Encrypts a file in 64MB streaming chunks using sequence-incremented nonces.
    Prevents high memory resident spikes on files > 1 GB.
    """
    aesgcm = AESGCM(key)
    seq = 0
    with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
        while True:
            chunk = fin.read(STREAM_CHUNK_SIZE)
            if not chunk:
                break
            nonce = seq.to_bytes(12, 'big')
            ciphertext = aesgcm.encrypt(nonce, chunk, None)
            fout.write(len(ciphertext).to_bytes(4, 'big'))
            fout.write(ciphertext)
            seq += 1

def stream_decrypt_file(input_path: str, output_path: str, key: bytes):
    """
    Decrypts a file in streaming chunks using sequence-incremented nonces.
    """
    aesgcm = AESGCM(key)
    seq = 0
    with open(input_path, "rb") as fin, open(output_path, "wb") as fout:
        while True:
            len_bytes = fin.read(4)
            if not len_bytes:
                break
            ct_len = int.from_bytes(len_bytes, 'big')
            ciphertext = fin.read(ct_len)
            nonce = seq.to_bytes(12, 'big')
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            fout.write(plaintext)
            seq += 1

def benchmark_large_file():
    print(f"\n[*] Starting Streaming Large File Benchmark ({LARGE_FILE_SIZE_MB} MB)...")
    
    large_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "benchmark_large.bin"))
    enc_file = large_file + ".enc"
    dec_file = large_file + ".dec"
    
    chunk_size = 10 * 1024 * 1024  # 10 MB chunks for file generation
    chunks = LARGE_FILE_SIZE_MB // 10
    
    try:
        key = AESGCM.generate_key(bit_length=256)
        
        # 1. Create dummy file on disk in 10MB chunks
        print("  [+] Creating 1.1 GB payload file on disk...")
        dummy_chunk = secrets.token_bytes(chunk_size)
        with open(large_file, "wb") as f:
            for _ in range(chunks):
                f.write(dummy_chunk)
        del dummy_chunk
        gc.collect()
        
        mem_baseline = get_max_memory_mb()
        print(f"  [+] Memory RSS baseline: {mem_baseline:.2f} MB")

        # 2. Stream Encryption (64MB chunks)
        print("  [+] Running AES-256-GCM Streaming Encryption on 1.1 GB payload...")
        start_enc = time.perf_counter()
        stream_encrypt_file(large_file, enc_file, key)
        enc_time = time.perf_counter() - start_enc
        enc_throughput = LARGE_FILE_SIZE_MB / enc_time

        gc.collect()
        mem_after_enc = get_max_memory_mb()

        # 3. Stream Decryption (64MB chunks)
        print("  [+] Running AES-256-GCM Streaming Decryption on 1.1 GB payload...")
        start_dec = time.perf_counter()
        stream_decrypt_file(enc_file, dec_file, key)
        dec_time = time.perf_counter() - start_dec
        dec_throughput = LARGE_FILE_SIZE_MB / dec_time

        gc.collect()
        mem_after_dec = get_max_memory_mb()

        # Leakage audit
        mem_leak = max(0.0, mem_after_dec - mem_baseline)

        print(f"  [+] Encryption duration: {enc_time:.4f} seconds ({enc_throughput:.2f} MB/s)")
        print(f"  [+] Decryption duration: {dec_time:.4f} seconds ({dec_throughput:.2f} MB/s)")
        print(f"  [+] Max Memory RSS after stream ops: {mem_after_dec:.2f} MB (Delta: {mem_leak:.2f} MB)")

        # Cleanup files
        for p in [large_file, enc_file, dec_file]:
            if os.path.exists(p):
                os.remove(p)

        return {
            "enc_time_s": enc_time,
            "enc_throughput_mbs": enc_throughput,
            "dec_time_s": dec_time,
            "dec_throughput_mbs": dec_throughput,
            "leakage_mb": mem_leak
        }
    except Exception as e:
        for p in [large_file, enc_file, dec_file]:
            if os.path.exists(p):
                try:
                    os.remove(p)
                except Exception:
                    pass
        print(f"  [-] Large file benchmark failed: {str(e)}")
        raise e

def database_worker(thread_id, results):
    """Worker thread performing continuous writes and reads against SQLite database."""
    writes = 0
    reads = 0
    start_time = time.perf_counter()
    
    conn = db.get_db()
    cursor = conn.cursor()
    
    for i in range(QUERIES_PER_THREAD):
        try:
            cursor.execute(
                "INSERT INTO audit_logs (timestamp, level, message, operator) VALUES (?, ?, ?, ?)",
                ("2026-08-09T00:00:00Z", "INFO", f"Benchmark query write thread {thread_id} op {i}", "BENCHMARK_BOT")
            )
            conn.commit()
            writes += 1
        except Exception:
            pass
            
        try:
            cursor.execute("SELECT COUNT(*) FROM audit_logs")
            cursor.fetchone()
            reads += 1
        except Exception:
            pass
            
    conn.close()
    duration = time.perf_counter() - start_time
    results.append({
        "writes": writes,
        "reads": reads,
        "duration": duration
    })

def benchmark_database():
    print(f"\n[*] Starting SQLite Database Stress Test ({DB_THREADS} Threads, {QUERIES_PER_THREAD * 2} Queries/Thread)...")
    
    db.init_db()
    threads = []
    results = []
    
    start_db = time.perf_counter()
    for i in range(DB_THREADS):
        t = threading.Thread(target=database_worker, args=(i, results))
        threads.append(t)
        t.start()
        
    for t in threads:
        t.join()
        
    total_db_time = time.perf_counter() - start_db
    total_writes = sum(r["writes"] for r in results)
    total_reads = sum(r["reads"] for r in results)
    total_ops = total_writes + total_reads
    avg_latency = sum(r["duration"] for r in results) / DB_THREADS
    qps = total_ops / total_db_time
    
    print(f"  [+] Completed {total_ops} database operations (Writes: {total_writes}, Reads: {total_reads})")
    print(f"  [+] Total execution duration: {total_db_time:.4f} seconds")
    print(f"  [+] Query throughput rate: {qps:.2f} operations/sec")
    
    return {
        "total_ops": total_ops,
        "total_time_s": total_db_time,
        "qps": qps,
        "avg_thread_latency_s": avg_latency
    }

def print_report(crypto_res, large_res, db_res, memory_usage_mb):
    print("\n" + "="*60)
    print("                 SECUREVAULT PERFORMANCE REPORT CARD")
    print("="*60)
    print(f"  OPERATING SYSTEM PLATFORM : {sys.platform.upper()}")
    print(f"  PYTHON KERNEL ENGINE      : {sys.version.split()[0]}")
    print(f"  MAX MEMORY RESIDENT (RSS) : {memory_usage_mb:.2f} MB")
    print("-"*60)
    print("  1. CRYPTOGRAPHIC ALGORITHMS (50 MB PAYLOAD):")
    print(f"     PBKDF2 Key Derivation  : {crypto_res['kdf_time_s']*1000:.2f} ms")
    print(f"     AES-256-GCM Encrypt    : {crypto_res['enc_throughput_mbs']:.2f} MB/s ({crypto_res['enc_time_s']:.4f} s)")
    print(f"     AES-256-GCM Decrypt    : {crypto_res['dec_throughput_mbs']:.2f} MB/s ({crypto_res['dec_time_s']:.4f} s)")
    print("-"*60)
    print("  2. STREAMING CRYPTO ALGORITHMS (1.1 GB PAYLOAD):")
    print(f"     AES-256-GCM Encrypt    : {large_res['enc_throughput_mbs']:.2f} MB/s ({large_res['enc_time_s']:.4f} s)")
    print(f"     AES-256-GCM Decrypt    : {large_res['dec_throughput_mbs']:.2f} MB/s ({large_res['dec_time_s']:.4f} s)")
    print(f"     Memory Leakage Delta   : {large_res['leakage_mb']:.2f} MB")
    print("-"*60)
    print("  3. DATABASE TRANSACTION ENGINE:")
    print(f"     Concurrency Stress Load: {DB_THREADS} Threads")
    print(f"     Total Queries Executed : {db_res['total_ops']} ops")
    print(f"     Mean Transaction Lat   : {db_res['avg_thread_latency_s']:.4f} s")
    print(f"     Throughput Efficiency  : {db_res['qps']:.2f} QPS")
    print("="*60 + "\n")

if __name__ == "__main__":
    print("[*] Launching SecureVault System Load Evaluator...")
    print("-" * 60)
    crypto = benchmark_crypto()
    large = benchmark_large_file()
    database = benchmark_database()
    mem = get_max_memory_mb()
    print_report(crypto, large, database, mem)
