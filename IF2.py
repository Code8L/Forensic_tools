from __future__ import print_function
import argparse

from PIL import Image
from PIL.ExifTags import TAGS

import simplekml
import sys


parser = argparse.ArgumentParser('Metadata from images')
parser.add_argument('PICTURE_FILE', help="Path to picture")
args = parser.parse_args()


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
    img_file = Image.open(args.PICTURE_FILE)
    exif_data = img_file._getexif()

    if exif_data is None:
        print("No EXIF data found")
        sys.exit()

    gps_info = exif_data.get(34853)  # GPSInfo tag

    if gps_info is None:
        print("No GPSInfo found in the image")
        sys.exit()

    lat_ref = gps_info[1]  # Latitude reference (N/S)
    lat = process_coords(gps_info[2])  # Latitude
    if lat_ref == 'S':
        lat = -lat

    lon_ref = gps_info[3]  # Longitude reference (E/W)
    lon = process_coords(gps_info[4])  # Longitude
    if lon_ref == 'W':
        lon = -lon


    kml = simplekml.Kml()
    kml.newpoint(name=args.PICTURE_FILE, coords=[(lon, lat)])
    kml.save(args.PICTURE_FILE + ".kml")

    print("GPS Coordinates: {}, {}".format(lat, lon))
    print("Google Maps URL: {}".format(gmaps.format(lat, lon)))
    print("OpenStreetMap URL: {}".format(open_maps.format(lat, lon)))
    print("KML File {} created".format(args.PICTURE_FILE + ".kml"))


if __name__ == '__main__':
    main()
    input("Press Enter to exit...")
