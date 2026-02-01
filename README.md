sudo kill -9 $(sudo lsof -t -i:8080)
  298  nohup python -u main.py > output.log 2>&1 &
  299  cat output.log
  
