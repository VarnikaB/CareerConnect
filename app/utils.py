import os
import secrets
from typing import Final

from flask import current_app, flash
from PIL import Image
from werkzeug.datastructures import FileStorage

POST_IMAGE_SIZE: Final = (800, 800)
PROFILE_IMAGE_SIZE: Final = (200, 200)


def save_post(post_image: FileStorage) -> str:
    hex_random = secrets.token_hex(8)
    _, file_extension = os.path.splitext(post_image.filename or "")
    post_filename = hex_random + file_extension
    post_path = os.path.join(current_app.root_path, "static/posts", post_filename)

    try:
        i = Image.open(post_image)
        i.thumbnail(POST_IMAGE_SIZE)
        i.save(post_path)
    except Exception as e:
        flash(f"Couldn't save post image: {e}", "danger")

    return post_filename


def save_profile(prof_image: FileStorage) -> str:
    hex_random = secrets.token_hex(8)
    _, file_extension = os.path.splitext(prof_image.filename or "")
    profile_filename = hex_random + file_extension
    profile_path = os.path.join(current_app.root_path, "static/profile", profile_filename)

    try:
        i = Image.open(prof_image)
        i.thumbnail(PROFILE_IMAGE_SIZE)
        i.save(profile_path)
    except Exception as e:
        flash(f"Couldn't save profile image: {e}", "danger")

    return profile_filename
