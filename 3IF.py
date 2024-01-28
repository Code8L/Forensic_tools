from __future__ import print_function
import argparse

from PIL import Image
from PIL.ExifTags import TAGS

import simplekml
import sys


gmaps = "https://www.google.com/maps?q={},{}"
open_maps = "http://www.openstreetmap.org/?mlat={}&mlon={}"


def process_coords(coord):
    coord_deg = 0

    # Check if coord is a single value, convert it to a tuple
    if not isinstance(coord, tuple):
        coord = (coord,)

    for count, value in enumerate(coord):
        coord_deg += (float(value)) / 60**count
    return coord_deg



def main():

    print("[+]Created By: Lumene Caleb \n[+]Student Number: 1902114243\n[+]Course: Ethical Hacking")
    print("[+]Lecturers: Eng Mwashi, Eng Simata\n[+]Project title: Image GeoInfo Extract")
    print("##### NB: WHEN ADDING FILE PATH DONT USE DOUBLE QOUTES JUST ADD FILE LIKE SO: c/user/image.extension ####\n")
    while True:
        file_path = input("Enter the file path of the image (or 'exit' to quit): ")

        if file_path.lower() == 'exit':
            print("Exiting the program...")
            break

        try:
            img_file = Image.open(file_path)
            exif_data = img_file._getexif()

            if exif_data is None:
                print("No EXIF data found")
                continue

            gps_info = exif_data.get(34853)  # GPSInfo tag

            if gps_info is None:
                print("No GPSInfo found in the image")
                continue

            lat_ref = gps_info[1]  # Latitude reference (N/S)
            lat = process_coords(gps_info[2])  # Latitude
            if lat_ref == 'S':
                lat = -lat

            lon_ref = gps_info[3]  # Longitude reference (E/W)
            lon = process_coords(gps_info[4])  # Longitude
            if lon_ref == 'W':
                lon = -lon

            kml = simplekml.Kml()
            kml.newpoint(name=file_path, coords=[(lon, lat)])
            kml.save(file_path + ".kml")

            print("GPS Coordinates: {}, {}".format(lat, lon))
            print("Google Maps URL: {}".format(gmaps.format(lat, lon)))
            print("OpenStreetMap URL: {}".format(open_maps.format(lat, lon)))
            print("KML File {} created".format(file_path + ".kml"))

        except FileNotFoundError:
            print("File not found. Please try again.")

        except Exception as e:
            print("An error occurred: {}".format(str(e)))

        finally:
            print()  # Print a blank line for readability


if __name__ == '__main__':
    main()
    input("Press Enter to exit...")
