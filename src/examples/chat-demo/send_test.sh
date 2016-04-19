#!/bin/bash

# Send lots of messages to the server.

CYCLES=100

while [ $CYCLES -gt 0 ]; do

  ./risp_chat_send -n "Marley" -m "Yo, big daddy" &
  ./risp_chat_send -n "Wilber" -m "Hey there" &
  ./risp_chat_send -n "Marley" -m "Wassup?" &
  ./risp_chat_send -n "Wilber" -m "Not Much, you?" &
  ./risp_chat_send -n "Marley" -m "Same" &
  ./risp_chat_send -n "Franken" -m "Hi Guys" &
  ./risp_chat_send -n "Wilber" -m "Yo" &
  wait $!

  CYCLES=$((CYCLES-1))
done
