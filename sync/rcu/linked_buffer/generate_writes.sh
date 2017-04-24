#!/bin/bash

buf_1="$(printf 'A%.0s' {1..100})"
buf_2="$(printf 'E%.0s' {1..100})"
buf_3="$(printf 'O%.0s' {1..100})"

(echo ${buf_1} > /dev/linked &)
(echo ${buf_2} > /dev/linked &)
(echo ${buf_3} > /dev/linked &)

