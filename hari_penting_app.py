import streamlit as st
import schedule
import time
import datetime
import requests
import re
import pandas as pd
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from pymongo import MongoClient
import threading
import matplotlib.pyplot as plt
import seaborn as sns

# --- SCRAPING FUNGSI ---
def get_tanggalan_data():
    current_year = datetime.datetime.now().year

    options = Options()
    options.add_argument('--headless=new')
    options.add_argument('--disable-gpu')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')

    driver = webdriver.Chrome(options=options)
    driver.get("https://tanggalan.com/")
    time.sleep(3)
    page_text = driver.find_element("tag name", "body").text
    driver.quit()

    bulan_list = ['Januari', 'Februari', 'Maret', 'April', 'Mei', 'Juni',
                  'Juli', 'Agustus', 'September', 'Oktober', 'November', 'Desember']

    data = []
    current_bulan = ""

    for line in page_text.split('\n'):
        line = line.strip()
        if any(bulan.lower() in line.lower() for bulan in bulan_list) and str(current_year) in line:
            for b in bulan_list:
                if b.lower() in line.lower():
                    current_bulan = b
                    break
        else:
            match = re.match(r'^(\d{1,2})\s*(.+)', line)
            if match and current_bulan:
                tanggal = match.group(1)
                peringatan = match.group(2).strip()
                if not peringatan.isdigit():
                    bulan_numerik = str(bulan_list.index(current_bulan) + 1).zfill(2)
                    tanggal_format = f"{tanggal.zfill(2)}-{bulan_numerik}"
                    data.append({"Tanggal": tanggal_format, "Peringatan": peringatan})
    return data

def get_wikipedia_data():
    url = "https://id.wikipedia.org/wiki/Daftar_hari_penting_di_Indonesia"
    response = requests.get(url)
    soup = BeautifulSoup(response.content, "html.parser")

    bulan_valid = ['Januari', 'Februari', 'Maret', 'April', 'Mei', 'Juni',
                   'Juli', 'Agustus', 'September', 'Oktober', 'November', 'Desember']

    hari_penting = []
    pattern = re.compile(r"(\d{1,2})\s+(\w+)\s*(.*)")
    lists = soup.find_all(["ul", "ol"])

    for lst in lists:
        for li in lst.find_all("li"):
            text = li.get_text().strip()
            match = pattern.match(text)
            if match:
                tanggal, bulan, peringatan = match.group(1), match.group(2), match.group(3).strip()
                if bulan in bulan_valid and not re.search(r"\d{4}", peringatan):
                    bulan_numerik = str(bulan_valid.index(bulan) + 1).zfill(2)
                    tanggal_format = f"{tanggal.zfill(2)}-{bulan_numerik}"
                    hari_penting.append({"Tanggal": tanggal_format, "Peringatan": peringatan})
    return hari_penting

# --- DATABASE ---
def save_to_mongo(data):
    client = MongoClient("mongodb+srv://zidanreksa789:zidan08280904@praktikum.wrjzppn.mongodb.net/?retryWrites=true&w=majority&appName=praktikum")
    db = client.hari_penting
    collection = db.peringatan

    for item in data:
        collection.update_one(
            {"Tanggal": item["Tanggal"], "Peringatan": item["Peringatan"]},
            {"$set": item},
            upsert=True
        )

# --- RUN SCRAPER ---
def run_scraper():
    try:
        tanggalan = get_tanggalan_data()
        wikipedia = get_wikipedia_data()
        combined = tanggalan + wikipedia
        save_to_mongo(combined)
        print(f"[{datetime.datetime.now()}] ✅ Data berhasil diperbarui.")
    except Exception as e:
        print(f"[ERROR] Gagal scraping: {e}")

# --- JADWAL SCRAPING (JAM 07:00) ---
def schedule_thread():
    schedule.every().day.at("07:00").do(run_scraper)
    while True:
        schedule.run_pending()
        time.sleep(60)

# Jalankan penjadwalan di thread terpisah agar tidak mengganggu Streamlit
threading.Thread(target=schedule_thread, daemon=True).start()

# --- STREAMLIT APP ---
st.set_page_config(page_title="Hari Penting Indonesia", layout="wide")
st.title("📅 Daftar Hari Penting di Indonesia")

client = MongoClient("mongodb+srv://zidanreksa789:zidan08280904@praktikum.wrjzppn.mongodb.net/?retryWrites=true&w=majority&appName=praktikum")
collection = client.hari_penting.peringatan
data = list(collection.find({}, {"_id": 0}))
df = pd.DataFrame(data).sort_values(by="Tanggal")

# --- VISUALISASI 1: Grafik jumlah peringatan per bulan ---
st.subheader("📊 Jumlah Peringatan per Bulan")
bulan_count = df['Tanggal'].apply(lambda x: x.split('-')[1]).value_counts().sort_index()
fig1, ax1 = plt.subplots()
sns.barplot(x=bulan_count.index, y=bulan_count.values, ax=ax1)
ax1.set_xlabel('Bulan')
ax1.set_ylabel('Jumlah Peringatan')
ax1.set_title('Jumlah Peringatan per Bulan')
st.pyplot(fig1)

# --- FITUR PENCARIAN HARI PENTING ---
st.subheader("🔍 Cari Hari Penting")

search_keyword = st.text_input("Masukkan kata kunci peringatan (misal: kemerdekaan, guru, anak, dll):").lower()

if search_keyword:
    filtered_df = df[df['Peringatan'].str.lower().str.contains(search_keyword)]
    st.write(f"Menampilkan {len(filtered_df)} hasil untuk kata kunci: **{search_keyword}**")
    st.dataframe(filtered_df, use_container_width=True)
else:
    st.write("Masukkan kata kunci untuk mencari peringatan tertentu.")


# --- VISUALISASI 3: Tabel Peringatan berdasarkan Bulan ---
st.subheader("📅 Tabel Peringatan")
bulan = st.selectbox("Filter Bulan", ["Semua"] + sorted(set(t.split("-")[1] for t in df["Tanggal"])))
if bulan != "Semua":
    df = df[df["Tanggal"].str.contains(f"-{bulan}")]

st.dataframe(df, use_container_width=True)
