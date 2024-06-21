import os
import time
import ffmpeg
import boto3
from datetime import datetime
from botocore.exceptions import NoCredentialsError
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# Path to the existing AES key file
AES_KEY_PATH = r"C:\Users\HP\OneDrive\Documents\Github\downloadLive\aes.key"

def load_key_from_file(key_path):
    print(f"Loading AES key from {key_path}")
    with open(key_path, 'rb') as key_file:
        return key_file.read()

def encrypt_file(source_path, destination_path, key):
    print(f"Starting encryption of {source_path}")
    iv = b'\x00' * 16  # Fixed IV of 16 bytes of zeros
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()

    with open(source_path, 'rb') as f:
        data = f.read()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    if os.path.exists(destination_path):
        os.remove(destination_path)
    
    with open(destination_path, 'wb') as f:
        f.write(encrypted_data)
    print(f"Finished encryption of {source_path}")

def create_key_info_file(key_path, key_uri, key_info_file_path):
    print(f"Creating key info file at {key_info_file_path}")
    if os.path.exists(key_info_file_path):
        os.remove(key_info_file_path)
    with open(key_info_file_path, 'w') as f:
        f.write(f"{key_uri}\n")
        f.write(f"{key_path}\n")
    print(f"Key info file created at {key_info_file_path}")

def download_live_hls_clip(hls_url, output_filename, duration):
    print(f"Starting download of {duration}-second clip from {hls_url}")
    if os.path.exists(output_filename):
        os.remove(output_filename)
    try:
        start_time = time.time()
        process = (
            ffmpeg
            .input(hls_url, t=duration)
            .output(output_filename, format='mp4', vcodec='libx264', acodec='aac', ac=2, movflags='faststart')
            .run_async(pipe_stdout=True, pipe_stderr=True)
        )
        
        while process.poll() is None:
            output = process.stderr.readline().decode('utf-8')
            if output:
                print(output.strip())
        
        print(f"{duration}-second live HLS clip downloaded and saved as {output_filename} in {time.time() - start_time:.2f} seconds")
    except ffmpeg.Error as e:
        print(f"Error downloading HLS clip: {e.stderr.decode()}")
        raise

def ensure_ios_compatibility(input_filename, output_filename):
    print(f"Ensuring iOS compatibility for {input_filename}")
    if os.path.exists(output_filename):
        os.remove(output_filename)
    start_time = time.time()
    try:
        (
            ffmpeg
            .input(input_filename)
            .output(output_filename, vcodec='libx264', acodec='aac', ac=2, movflags='faststart')
            .run(capture_stdout=True, capture_stderr=True)
        )
        print(f"Ensured iOS compatibility for {input_filename}, saved as {output_filename} in {time.time() - start_time:.2f} seconds")
    except ffmpeg.Error as e:
        print(f"Error ensuring iOS compatibility: {e.stderr.decode()}")
        raise

def convert_mp4_to_hls(input_filename, output_dir, playlist_name, segment_time, profile='main'):
    print(f"Converting {input_filename} to HLS")
    output_prefix = os.path.join(output_dir, 'segment')
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    try:
        start_time = time.time()
        (
            ffmpeg
            .input(input_filename)
            .output(
                os.path.join(output_dir, playlist_name),
                format='hls',
                hls_time=segment_time,
                hls_segment_filename=os.path.join(output_dir, 'segment%d.ts'),
                hls_list_size=0,
                force_key_frames=f"expr:gte(t,n_forced*{segment_time})",
                profile=profile,
                level='5.0',
                ac=2  # Ensure audio channels are 2
            )
            .run(capture_stdout=True, capture_stderr=True)
        )
        print(f"Converted {input_filename} to HLS with playlist {playlist_name} using profile {profile} in {time.time() - start_time:.2f} seconds")
    except ffmpeg.Error as e:
        stderr_output = e.stderr.decode() if e.stderr else "No stderr output available"
        print(f"FFmpeg error: {stderr_output}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

def encrypt_hls_segments(output_dir, key):
    print(f"Starting encryption of HLS segments in {output_dir}")
    for root, dirs, files in os.walk(output_dir):
        for file in files:
            if file.endswith(".ts"):
                source_path = os.path.join(root, file)
                destination_path = source_path + ".enc"
                encrypt_file(source_path, destination_path, key)
                os.remove(source_path)  # Remove the unencrypted file
                os.rename(destination_path, source_path)  # Rename the encrypted file back to the original
    print(f"Finished encryption of HLS segments in {output_dir}")

def modify_m3u8_file(m3u8_file_path, key_uri):
    print(f"Modifying M3U8 file at {m3u8_file_path}")
    if not os.path.exists(m3u8_file_path):
        print(f"Error: M3U8 file not found at {m3u8_file_path}")
        return False

    with open(m3u8_file_path, 'r') as f:
        lines = f.readlines()

    # Add the encryption key line after the media sequence line
    for i in range(len(lines)):
        if lines[i].startswith('#EXT-X-MEDIA-SEQUENCE:'):
            lines.insert(i + 1, f'#EXT-X-KEY:METHOD=AES-128,URI="{key_uri}"\n')
            break

    # Remove #EXT-X-PLAYLIST-TYPE:VOD if it exists
    lines = [line for line in lines if not line.startswith('#EXT-X-PLAYLIST-TYPE:VOD')]

    with open(m3u8_file_path, 'w') as f:
        f.writelines(lines)
    print(f"Modified M3U8 file at {m3u8_file_path}")
    return True

def upload_hls_to_s3(directory, bucket, prefix):
    print(f"Starting upload of HLS files from {directory} to S3 bucket {bucket}")
    s3_client = boto3.client('s3')
    start_time = time.time()
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(".ts") or file.endswith(".m3u8"):
                file_path = os.path.join(root, file)
                object_name = os.path.join(prefix, file).replace("\\", "/")
                try:
                    s3_client.upload_file(file_path, bucket, object_name)
                    print(f"File uploaded successfully to {bucket}/{object_name}")
                except NoCredentialsError:
                    print("Credentials not available")
                except FileNotFoundError:
                    print(f"File not found: {file_path}")
                except Exception as e:
                    print(f"Error uploading file to S3: {e}")
    print(f"Finished upload of HLS files to S3 bucket {bucket} in {time.time() - start_time:.2f} seconds")

def create_upload_time_file(file_path):
    print(f"Creating upload time file at {file_path}")
    upload_time = datetime.now().strftime('%d/%m/%Y %I:%M %p')
    if os.path.exists(file_path):
        os.remove(file_path)
    with open(file_path, 'w') as f:
        f.write(f"{upload_time}\n")
    print(f"Upload time file created at {file_path}")

def upload_to_s3(file_name, bucket, object_name=None):
    print(f"Starting upload of {file_name} to S3 bucket {bucket}")
    if object_name is None:
        object_name = file_name

    s3_client = boto3.client('s3')

    start_time = time.time()
    try:
        s3_client.upload_file(file_name, bucket, object_name.replace("\\", "/"))
        print(f"File uploaded successfully to {bucket}/{object_name.replace('\\', '/')} in {time.time() - start_time:.2f} seconds")
    except NoCredentialsError:
        print("Credentials not available")
    except FileNotFoundError:
        print(f"File not found: {file_name}")
    except Exception as e:
        print(f"Error uploading file to S3: {e}")

def main():
    hls_url = 'http://192.168.0.48:8000/tmp/live/live.m3u8'
    bucket_name = 'co.techxr.system.backend.upload.dev'
    object_name_prefix = 'aajKeDarshan'
    ios_prefix = f'{object_name_prefix}/ios'
    duration = 15  # Duration of each clip in seconds
    num_clips = 4  # Four 15-second clips to make up a 1-minute clip
    output_dir = 'output_hls'
    segment_time = 4  # Duration of each HLS segment in seconds
    playlist_name = 'live.m3u8'  # Name of the playlist file
    clip_filenames = []

    try:
        # Load the AES key from the file
        key = load_key_from_file(AES_KEY_PATH)
        key_uri = "encrypt_key.key"

        # Create the key info file
        key_info_file = 'key_info_file.txt'
        create_key_info_file(AES_KEY_PATH, f"https://{bucket_name}.s3.amazonaws.com/{key_uri}", key_info_file)

        # Download 15-second clips every minute
        for i in range(num_clips):
            clip_filename = f'clip_part_{i}.mp4'
            download_live_hls_clip(hls_url, clip_filename, duration)
            clip_filenames.append(clip_filename)
            if i < num_clips - 1:
                time.sleep(60)  # Wait for 1 minute before downloading the next clip

        # Concatenate the downloaded clips into a single file
        concat_filename = 'clip_concat.mp4'
        with open('file_list.txt', 'w') as file_list:
            for clip_filename in clip_filenames:
                file_list.write(f"file '{os.path.abspath(clip_filename)}'\n")
        
        ffmpeg.input('file_list.txt', format='concat', safe=0).output(concat_filename, c='copy').run()

        # Ensure the concatenated file is compatible with iOS
        ios_compatible_filename = 'clip_ios.mp4'
        ensure_ios_compatibility(concat_filename, ios_compatible_filename)

        # Convert the combined MP4 file to HLS with profile set to 'main'
        os.makedirs(output_dir, exist_ok=True)
        convert_mp4_to_hls(ios_compatible_filename, output_dir, playlist_name, segment_time, profile='main')

        # Verify the M3U8 file exists
        m3u8_file_path = os.path.join(output_dir, playlist_name)
        if not os.path.exists(m3u8_file_path):
            print(f"Error: M3U8 file not found at {m3u8_file_path}")
            return

        # Upload the unencrypted HLS files to S3 (ios prefix)
        upload_hls_to_s3(output_dir, bucket_name, ios_prefix)

        # Encrypt the HLS segments
        encrypt_hls_segments(output_dir, key)

        # Modify the M3U8 file to add the encryption key
        if not modify_m3u8_file(m3u8_file_path, f"https://{bucket_name}.s3.amazonaws.com/{key_uri}"):
            print("Error modifying the M3U8 file")
            return

        # Upload the encrypted HLS files and the playlist to S3
        upload_hls_to_s3(output_dir, bucket_name, object_name_prefix)

        # Create and upload the upload time file
        upload_time_file = 'upload_time.txt'
        create_upload_time_file(upload_time_file)
        upload_to_s3(upload_time_file, bucket_name, f"{object_name_prefix}/upload_time.txt")

        # Clean up the individual clip files
        for clip_filename in clip_filenames:
            os.remove(clip_filename)
        os.remove(concat_filename)
        os.remove(ios_compatible_filename)
        os.remove('file_list.txt')

        # Optionally, clean up the HLS files
        import shutil
        shutil.rmtree(output_dir)

        print("Process completed successfully.")

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    main()
