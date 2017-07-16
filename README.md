## Cara Penggunaan

1. Install Docker
2. Satu folder dengan Dockerfile, jalankan : `docker build -t ryu-mininet` .
3. `docker create -it --rm --privileged -e DISPLAY -v /tmp.X11-unix:/temp/.X11-unix -v /lib/modules:/lib
/modules -v D:/folder/di/mana/Dockerfile/berada:/data ryu-mininet`
4. Perhatikan hash yg dihasilkan, contoh: b7180c1ee30eb81fd2902a4877bb6c11aeebe8961f12201c0fcb84723e21cf26
5. `docker start b7180c1ee30eb81fd2902a4877bb6c11aeebe8961f12201c0fcb84723e21cf26`
6. `docker exec -it b7180c1ee30eb81fd2902a4877bb6c11aeebe8961f12201c0fcb84723e21cf26 bash`
7. Buka cmd atau terminal baru, jalankan no 6. lagi
8. Pada masing-masing terminal, pindah ke folder `/data` : `cd /data`
8. Pada terminal 1, jalankan controller, contoh: `ryu-manager --observe-links dijkstra_delay.py`
9. Pada terminal 2, jalankan topology: `python topo2.py`
10. Jalankan perintah seperti di mininet, contoh: `h2 ping 10.0.0.1`
