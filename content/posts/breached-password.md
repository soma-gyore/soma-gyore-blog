---
title: "Breached password detection a.k.a. binary search and indexing in action"
date: 2022-04-09T20:38:38+02:00
draft: false
---

# Introduction

According to an [Online Security Survey](https://services.google.com/fh/files/blogs/google_security_infographic.pdf) *conducted by Google/Harris Poll* 
- 52% of the people reuse the same password for multiple accounts and 
- 13% of them reuse the same password for **all** of their accounts.

This doesn't look so good. There's a great chance that the user credentials leaked from 'site A' will also leave the door open for attackers at 'site B'. 

You can protect your users from loosing control over multiple accounts by checking their passwords:
- **at login:** notify them (or even block them) if their existing password was part of a data breach
- **at registration:** do not allow the use of a breached password.

Good thing there's a database known to humankind as [haveibeenpwned (HIBP)](https://haveibeenpwned.com/Passwords) to lend you a helping hand.

The database is a text file that contains the leaked passwords hashes followed by the exact count of how many times that password was seen in the source data breaches.

HIBP provides an [API](https://haveibeenpwned.com/API/v3) but here's the thing: it has a rate limit of one request per 1500 milliseconds. This means it isn't suitable for using it in production.

Yet, there is way, and this article is all about me showing you that way. 

Note*: There are multiple versions of the database and we're going to use the version that's ordered by hash. We'll discuss the *why* later.

# The problem

So, our task is to decide whether the breached password database contains the SHA1 hash of the given password as fast as possible with as low resource usage as possible.

The size of the HIBP breached password database is more than 36GB as of the writing this article (v8).

# The solution

## Linear search - too slow, too much resource usage

Linear search is the easiest solution to implement: you go through the file, line by line, and compare each line with the given hash. If there is a match: the password has been compromised. If we make it till the end of the whole file without any match then the password wasn't breached.

The biggest problem with this approach is that it uses lots of CPU and it runs for minutes. Especially if we assume that most of the users' passwords are not compromised (so the search will query through the whole file most of the time).

## Binary search

As I promised earlier, I'm going to explain the *why* about choosing the version of the breached password DB that's ordered by hash.

As Wikipedia says: 

> Binary search [...] is a search algorithm that finds the position of a target value within a sorted array.
>
> --- [Binary search algorithm. (2022, April 10). In Wikipedia, The Free Encyclopedia. Retrieved 11:57, April 10, 2022](https://en.wikipedia.org/wiki/Binary_search_algorithm)

We have a sorted "array" (that's actually a sorted text file) so it seems we can make good use of this algorithm to solve all of our performance problems.

There's more: our dataset has another property that we could take advantage of: **every hash has the same length!** (20 byte/40 characters because it's SHA1)

### Processing our data

First, we have to get our raw file in shape to suit our needs.

The database looks like this:

```
000000005AD76BD555C1D6D771DE417A4B87E4B4:10
00000000A8DAE4228F821FB418F59826079BF368:4
00000000DD7F2A1C68A35673713783CA390C9E93:873
00000001E225B908BAC31C56DB04D892E47536E0:6
...
```

#### Removing unnecessary characters 

We don't need the information on the number of occurrences. We can also remove the new lines so we can use position seeking (remember: hashes are the same length).

After processing, our data file will look a lot like this:

```
000000005AD76BD555C1D6D771DE417A4B87E4B400000000A8DAE4228F821FB418F59826079BF368...
```

Basically, we have one line and every 40 characters is a hash.

We're getting there, but we can still optimize our processed file. 

#### Store as a binary data

We can store the file as **binary data!** The file size will be cut in half compared to the size of the raw text version.

After processing, we get a ~16GB file. That's much better!

### Converting the DB
So our converter script will look like this:

``` python
raw_pwned_passwords_file = "pwned-passwords-sha1-ordered-by-hash-v8.txt"

with open("out.txt", "wb") as binary_file: # open the output file to writing a binary file 
    with open(raw_pwned_passwords_file, "r") as raw_file: # open the raw database file for reading
        for line in raw_file: # go through every line
            binary_file.write(bytes.fromhex(line[:40])) # write the first 40 characters of the line as binary data
```

It'll take a while to process the whole database but after it's done the size will be significantly smaller!

We shrank our database by more than half so it's definitely progress!

The binary search algorithm:

``` python
import os
import sys
import hashlib

searched_string = sys.argv[1]

searched_hash = hashlib.sha1(searched_string.encode("utf-8")).hexdigest().upper() # create a hash from the searched password

processed_db_file_path = "out.txt"

file_size = os.path.getsize(processed_db_file_path) # get the size of the password db

with open(processed_db_file_path, "rb") as file: # open the processed breached pw db file
    low = 0
    high = file_size//20 # we have file_size/20 hash in the file
    mid = 0
 
    while low <= high:
 
        mid = (high + low) // 2
 
        file.seek(mid*20)
        current_hash = file.read(20).hex().upper()
        
        if current_hash < searched_hash: # searched_hash is greater, ignore left half
            low = mid + 1
 
        elif current_hash > searched_hash: # searched_hash is smaller, ignore right half
            high = mid - 1

        else: # searched_hash is present at mid
            print("found")

    print("not found")
```

Much faster than the linear search.

Don't sit back just yet... we can take this a little further.

### Indexing

*So what if* during DB conversion we create an index file for our hashes.

We'll work with the first n bytes of the hashes. We'll store the information where the hashes start, for example: hashes starting with '01' start from 100 bytes in the database file, hashes starting with '02' start from 250 bytes, etc.

Then we read this index file into a variable. Thanks to this file, we need to check only a small range which means fewer I/O operations.

However, we need to choose carefully our index size (hash prefix). 
There are 2 things to take into cosideration: 

1. The DB should contain every possible hash prefix.
For example, if we use a 3-byte index then we have to make sure that our DB contains every possibility of the hash prefixes for the first 3 bytes/6 characters. So everything from *000000* to *FFFFFF*.
We can check this with the following command: 

    ```
    cat pwned-passwords-sha1-ordered-by-hash-v8.txt | colrm 7 | uniq | wc -l
    ```

    the output of this command is 

    ```
    16777216
    ```

    so it means that we have all of the hash prefixes from *000000* to *FFFFFF* (because it's 16^6 variations so 16777216)

2. How many memory we can use? 
    - 2-byte indexes use 16^4*8 byte, so ~65KB
    - 3-byte indexes use 16^6*8 byte so ~134MB
    - 4-byte indexes use 16^8*8 byte, so ~34 GB
    
A 4-byte index is not reasonable, so 2 or 3 bytes will be the best choice. 

Let's choose 3 bytes for our implementation and improve our DB generating script with index file generation.

``` python
raw_pwned_passwords_file = "pwned-passwords-sha1-ordered-by-hash-v8.txt"

prev_line = "000000"

with open("out.txt", "wb") as binary_file: # open hash output file for write as a binary file
    with open("index.txt", "w") as index_file: # open index file to write as a regular file
        with open(raw_pwned_passwords_file, "r") as raw_file: # open raw file for reading
            for line in raw_file: # read the raw file line by line
                if line[:6] != prev_line: # if there is a difference between the first 3 bytes then
                    index_file.write(str(binary_file.tell()) + "\n") # write the position to the index file
                    prev_line = line[:6]
                
                binary_file.write(bytes.fromhex(line[6:40])) # write the hash from 6th character to 40th
```

We have 2 files: 
  - one that contains the hashes 
  - one that has the positions where our hashes starts based on the first 3 bytes. 

We can cut the first 3 bytes off of the hashes because we already know where to look when we search for a hash.

``` python
import os
import sys
import hashlib

searched_string = sys.argv[1]

searched_hash = hashlib.sha1(searched_string.encode("utf-8")).hexdigest().upper()
print("searched password SHA1 hash: " + searched_hash)

processed_db_file_path = "out.txt"
index_file_path = "index.txt"

file_size = os.path.getsize(processed_db_file_path)

indexes = []

with open(index_file_path, "r") as index_file:
    indexes = list(map(int, index_file.read().splitlines()))

with open(processed_db_file_path, "rb") as hash_file:
     # the first 3 bytes of the hash represents the index of the indexes
     # i.e. if the searched hash starts with '000012' then we need the 18th position
    low = indexes[int(searched_hash[:6], 16)] // 20

    # max position is always n+1
    high = indexes[int(searched_hash[:6], 16)+1] // 20
    mid = 0

    while low <= high:

        mid = (high + low) // 2

        hash_file.seek(mid*20)
        hash = hash_file.read(20).hex().upper()

        if hash < searched_hash[6:]:
            low = mid + 1

        elif hash > searched_hash[6:]:
            high = mid - 1

        else:
            print("found")

    print("not found")
```

# Conclusion

If you want to implement breached password detection for your application and you don't want to rely on Have I been pwned API or their rate limit is too strict for your use case, this solution can be a viable option for your application.
