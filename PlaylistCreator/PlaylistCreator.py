import re
import aiohttp
from redbot.core import commands, Config, checks
from discord.ext import tasks
from collections import defaultdict
from base64 import b64encode
import logging
import discord
import asyncio
from aiohttp import web
import secrets
import base64
import hashlib
from urllib.parse import urlparse, parse_qs, quote, urlencode
import lyricsgenius
from datetime import datetime, timedelta
from discord import ui

# Add this list at the top of your file or in a separate configuration
OFFENSIVE_WORDS = ["fag", "nigger", "retard", "gay"]  # Add your list of offensive words here

class APICredentialsModal(ui.Modal, title='API Credentials'):
    spotify_client_id = ui.TextInput(label='Spotify Client ID', placeholder='Enter your Spotify Client ID')
    spotify_client_secret = ui.TextInput(label='Spotify Client Secret', placeholder='Enter your Spotify Client Secret', style=discord.TextStyle.short)
    spotify_playlist_id = ui.TextInput(label='Spotify Playlist ID', placeholder='Enter your Spotify Playlist ID')
    genius_api_key = ui.TextInput(label='Genius API Key', placeholder='Enter your Genius API Key')

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True)
        cog = interaction.client.get_cog('URLGrabber')
        await cog.config.spotify_client_id.set(self.spotify_client_id.value)
        await cog.config.spotify_client_secret.set(self.spotify_client_secret.value)
        await cog.config.spotify_playlist_id.set(self.spotify_playlist_id.value)
        await cog.config.genius_api_key.set(self.genius_api_key.value)
        cog.genius = lyricsgenius.Genius(self.genius_api_key.value)
        await interaction.followup.send("API credentials set successfully!", ephemeral=True)

class SpotifyAuthModal(ui.Modal, title='Spotify Authorization'):
    auth_url = ui.TextInput(label='Authorization URL', style=discord.TextStyle.paragraph, placeholder='Paste the entire URL here after authorizing')

    async def on_submit(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True)
        self.auth_response = self.auth_url.value
        self.stop()

class URLGrabber(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.config = Config.get_conf(self, identifier=1234567890)
        default_global = {
            "channel_id": None,
            "user_id": None,
            "spotify_client_id": None,
            "spotify_client_secret": None,
            "spotify_playlist_id": None,
            "spotify_refresh_token": None,
            "added_tracks": [],
            "last_message_id": None,
            "genius_api_key": None,
        }
        self.config.register_global(**default_global)
        self.url_pattern = re.compile(r'https://open\.spotify\.com/track/([a-zA-Z0-9]+)')
        self.url_check.start()
        self.spotify_token = None
        self.spotify_token_expiry = None
        self.token_refresh_task = self.bot.loop.create_task(self.auto_refresh_token())
        self.logger = logging.getLogger("red.PlaylistCreator")
        self.logger.info("PlaylistCreator cog initialized")
        self.auth_code = None
        self.genius = None

    def cog_unload(self):
        self.url_check.cancel()
        if self.token_refresh_task:
            self.token_refresh_task.cancel()

    @commands.group()
    @commands.admin()
    async def playlistset(self, ctx):
        """Configure the PlaylistCreator settings."""
        self.logger.info("playlistset command invoked")
        if ctx.invoked_subcommand is None:
            await ctx.send_help(ctx.command)

    @playlistset.command(name="channel")
    @commands.admin()
    async def set_channel(self, ctx, channel_id: int):
        """Set the channel to monitor for Spotify links."""
        await self.config.channel_id.set(channel_id)
        await ctx.send(f"Channel set to {channel_id}")

    @playlistset.command(name="user")
    @commands.admin()
    async def set_user(self, ctx, user_id: int):
        """Set the user ID for Spotify authentication."""
        await self.config.user_id.set(user_id)
        await ctx.send(f"User ID set to {user_id}")

    @playlistset.command(name="spotify_client_id")
    @commands.admin()
    async def set_spotify_client_id(self, ctx, client_id: str):
        """Set the Spotify Client ID."""
        await self.config.spotify_client_id.set(client_id)
        await ctx.send("Spotify Client ID set.")

    @playlistset.command(name="spotify_client_secret")
    @commands.admin()
    async def set_spotify_client_secret(self, ctx, client_secret: str):
        """Set the Spotify Client Secret."""
        await self.config.spotify_client_secret.set(client_secret)
        await ctx.send("Spotify Client Secret set.")

    @playlistset.command(name="spotify_playlist_id")
    @commands.admin()
    async def set_spotify_playlist_id(self, ctx, playlist_id: str):
        """Set the Spotify Playlist ID."""
        await self.config.spotify_playlist_id.set(playlist_id)
        await ctx.send(f"Spotify Playlist ID set to {playlist_id}")

    @playlistset.command(name="genius_api_key")
    @commands.admin()
    async def set_genius_api_key(self, ctx, api_key: str):
        """Set the Genius API Key."""
        await self.config.genius_api_key.set(api_key)
        self.genius = lyricsgenius.Genius(api_key)
        await ctx.send("Genius API Key set.")

    @commands.command()
    @commands.admin()
    async def playlistsettings(self, ctx):
        """Show the current PlaylistCreator settings."""
        channel_id = await self.config.channel_id()
        user_id = await self.config.user_id()
        spotify_client_id = await self.config.spotify_client_id()
        spotify_playlist_id = await self.config.spotify_playlist_id()
        genius_api_key = await self.config.genius_api_key()

        settings = (
            f"Channel ID: {channel_id}\n"
            f"User ID: {user_id}\n"
            f"Spotify Client ID: {'Set' if spotify_client_id else 'Not set'}\n"
            f"Spotify Client Secret: {'Set' if await self.config.spotify_client_secret() else 'Not set'}\n"
            f"Spotify Playlist ID: {spotify_playlist_id}\n"
            f"Genius API Key: {'Set' if genius_api_key else 'Not set'}\n"
        )
        await ctx.send(f"Current settings:\n```\n{settings}\n```")

    @commands.command()
    @commands.admin()
    async def seturldm(self, ctx, user_id: int):
        """Set the user to send grabbed URLs to."""
        await self.config.user_id.set(user_id)
        await ctx.send(f"URL recipient set to user with ID {user_id}")

    @commands.command()
    @commands.admin()
    async def setapicredentials(self, ctx):
        """Set all API credentials using a single modal."""
        modal = APICredentialsModal()
        await ctx.send("Please fill out the API credentials form:", view=ui.View().add_item(ui.Button(label="Open Form", style=discord.ButtonStyle.primary, custom_id="open_api_modal")))

        def check(interaction):
            return interaction.data["custom_id"] == "open_api_modal" and interaction.user == ctx.author

        interaction = await self.bot.wait_for("interaction", check=check)
        await interaction.response.send_modal(modal)

    @commands.command()
    @commands.admin()
    async def graburl(self, ctx):
        """Manually trigger URL grabbing process."""
        self.logger.info("Manual URL grab triggered")
        channel_id = await self.config.channel_id()
        user_id = await self.config.user_id()
        if not channel_id or not user_id:
            await ctx.send("Please set both the channel and user ID first.")
            self.logger.warning("Channel ID or User ID not set")
            return

        await ctx.send("Manually triggering URL grab...")
        await self.perform_url_check()
        await ctx.send("URL grab complete.")
        self.logger.info("Manual URL grab completed")

    @tasks.loop(minutes=5.0)
    async def url_check(self):
        await self.perform_url_check()

    async def perform_url_check(self):
        channel_id = await self.config.channel_id()
        user_id = await self.config.user_id()
        self.logger.info(f"Performing URL check for channel {channel_id} and user {user_id}")
        
        if not channel_id or not user_id:
            self.logger.warning("Channel ID or User ID not set")
            return

        channel = self.bot.get_channel(channel_id)
        user = self.bot.get_user(user_id)

        if not channel or not user:
            self.logger.warning("Could not find channel or user")
            return

        url_dict = defaultdict(list)
        
        last_message_id = await self.config.last_message_id()
        self.logger.info(f"Last processed message ID: {last_message_id}")
        kwargs = {}
        if last_message_id:
            kwargs['after'] = discord.Object(id=int(last_message_id))
        
        message_count = 0
        async for message in channel.history(limit=None, oldest_first=True, **kwargs):
            message_count += 1
            self.logger.info(f"Checking message {message.id} from {message.author.name}")
            urls = re.findall(r'(https://open\.spotify\.com/track/[^\s]+)', message.content)
            if urls:
                self.logger.info(f"Found {len(urls)} Spotify URLs in message {message.id}")
                for url in urls:
                    track_id = self.sanitize_spotify_url(url)
                    if track_id:
                        url_dict[message.author.name].append(track_id)
                        self.logger.info(f"Added track ID {track_id} from {message.author.name}")
            await self.config.last_message_id.set(str(message.id))

        self.logger.info(f"Checked {message_count} messages")
        self.logger.info(f"Found {len(url_dict)} users with Spotify links")
        
        if url_dict:
            track_ids = list(set([track_id for tracks in url_dict.values() for track_id in tracks]))
            self.logger.info(f"Found {len(track_ids)} unique track IDs")
            await self.add_tracks_to_playlist(track_ids)
        else:
            self.logger.info("No new Spotify links found")

    def sanitize_spotify_url(self, url):
        """
        Sanitize and validate a Spotify track URL.
        Returns the track ID if valid, None otherwise.
        """
        match = self.url_pattern.match(url)
        if match:
            return match.group(1)
        return None

    @playlistset.command(name="clear_added_tracks")
    @commands.admin()
    async def clear_added_tracks(self, ctx):
        """Clear the list of tracks that have been added to the playlist."""
        await self.config.added_tracks.set([])
        await ctx.send("The list of added tracks has been cleared.")

    @commands.command()
    @commands.admin()
    async def auth(self, ctx):
        """Start the Spotify authentication process."""
        client_id = await self.config.spotify_client_id()
        if not client_id:
            await ctx.send("Spotify client ID is not set. Please set it first.")
            return

        code_verifier = secrets.token_urlsafe(64)
        code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).decode().rstrip('=')

        state = secrets.token_urlsafe(16)
        scope = "playlist-modify-public playlist-modify-private"
        redirect_uri = "https://example.com/callback"  # This should be set in your Spotify Developer Dashboard

        params = {
            "client_id": client_id,
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "scope": scope,
            "state": state,
            "code_challenge_method": "S256",
            "code_challenge": code_challenge,
        }

        auth_url = f"https://accounts.spotify.com/authorize?{urlencode(params)}"

        await ctx.send(f"Please click this link to authorize the application: {auth_url}\n"
                       f"After authorizing, you will be redirected. Click the button below to submit the URL.")

        view = ui.View()
        view.add_item(ui.Button(label="Submit Authorization URL", style=discord.ButtonStyle.green, custom_id="submit_auth"))

        await ctx.send("Click here when ready:", view=view)

        def check(interaction):
            return interaction.data["custom_id"] == "submit_auth" and interaction.user == ctx.author

        try:
            interaction = await self.bot.wait_for('interaction', timeout=300.0, check=check)
            modal = SpotifyAuthModal()
            await interaction.response.send_modal(modal)
            await modal.wait()
            
            auth_response = modal.auth_response

        except asyncio.TimeoutError:
            await ctx.send("You took too long to submit the URL. Please try again.")
            return

        code = self.extract_code_from_url(auth_response)
        
        if not code:
            await ctx.send("Could not find the authorization code in the URL. Please try again.")
            return

        success = await self.get_spotify_token(code, code_verifier)
        if success:
            await ctx.send("Spotify authentication complete!")
        else:
            await ctx.send("Failed to authenticate with Spotify. Please try again.")

    def extract_code_from_url(self, url):
        """Extract the authorization code from the callback URL."""
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        return query_params.get('code', [None])[0]

    async def get_spotify_token(self, code, code_verifier):
        client_id = await self.config.spotify_client_id()
        client_secret = await self.config.spotify_client_secret()
        redirect_uri = "https://example.com/callback"

        self.logger.info(f"Attempting to exchange code for token. Code: {code[:10]}...")

        async with aiohttp.ClientSession() as session:
            data = {
                "client_id": client_id,
                "client_secret": client_secret,
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "code_verifier": code_verifier,
            }
            self.logger.info(f"Token exchange data: {data}")

            async with session.post("https://accounts.spotify.com/api/token", data=data) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    self.spotify_token = data["access_token"]
                    self.spotify_token_expiry = datetime.now() + timedelta(seconds=data["expires_in"])
                    await self.config.spotify_refresh_token.set(data["refresh_token"])
                    self.logger.info("Successfully obtained Spotify token")
                    return True
                else:
                    error_text = await resp.text()
                    self.logger.error(f"Failed to get Spotify token. Status: {resp.status}, Response: {error_text}")
                    return False

    async def refresh_spotify_token(self):
        client_id = await self.config.spotify_client_id()
        client_secret = await self.config.spotify_client_secret()
        refresh_token = await self.config.spotify_refresh_token()

        if not refresh_token:
            self.logger.error("No refresh token available. Please re-authenticate.")
            return False

        async with aiohttp.ClientSession() as session:
            async with session.post(
                "https://accounts.spotify.com/api/token",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                    "client_id": client_id,
                    "client_secret": client_secret,
                }
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    self.spotify_token = data["access_token"]
                    self.spotify_token_expiry = datetime.now() + timedelta(seconds=data["expires_in"])
                    if "refresh_token" in data:
                        await self.config.spotify_refresh_token.set(data["refresh_token"])
                    return True
                else:
                    self.logger.error(f"Failed to refresh Spotify token. Status: {resp.status}")
                    return False

    async def get_lyrics(self, track_name, artist_name):
        if not self.genius:
            genius_api_key = await self.config.genius_api_key()
            if not genius_api_key:
                self.logger.error("Genius API key is not set")
                return None
            self.genius = lyricsgenius.Genius(genius_api_key)

        self.logger.info(f"Searching Genius for '{track_name}' by {artist_name}")
        try:
            song = self.genius.search_song(track_name, artist_name)
            if song:
                self.logger.info(f"Found lyrics for '{track_name}' by {artist_name}")
                return song.lyrics
            else:
                self.logger.info(f"No lyrics found for '{track_name}' by {artist_name}")
                return None
        except Exception as e:
            self.logger.error(f"Error fetching lyrics: {str(e)}")
            return None

    def contains_offensive_words(self, lyrics):
        if not lyrics:
            self.logger.info("No lyrics provided to check for offensive words")
            return False
        lowered_lyrics = lyrics.lower()
        for word in OFFENSIVE_WORDS:
            if word in lowered_lyrics:
                self.logger.info(f"Offensive word found: '{word}'")
                return True
        self.logger.info("No offensive words found in lyrics")
        return False

    async def add_tracks_to_playlist(self, track_ids):
        if not await self.ensure_spotify_token():
            return False

        self.logger.info(f"Attempting to add {len(track_ids)} tracks to playlist")
        if not self.spotify_token:
            success = await self.refresh_spotify_token()
            if not success:
                self.logger.error("Failed to refresh Spotify token")
                return False

        playlist_id = await self.config.spotify_playlist_id()
        if not playlist_id:
            self.logger.error("Spotify playlist ID not set")
            return False

        headers = {
            "Authorization": f"Bearer {self.spotify_token}",
            "Content-Type": "application/json"
        }

        self.logger.info("Fetching current tracks in the playlist")
        # Get current tracks in the playlist
        async with aiohttp.ClientSession() as session:
            async with session.get(f"https://api.spotify.com/v1/playlists/{playlist_id}/tracks", headers=headers) as resp:
                if resp.status == 200:
                    playlist_tracks = await resp.json()
                    current_track_ids = [item['track']['id'] for item in playlist_tracks['items']]
                    self.logger.info(f"Playlist currently has {len(current_track_ids)} tracks")
                else:
                    self.logger.error(f"Failed to get current playlist tracks. Status: {resp.status}")
                    return False

        # Get previously added tracks
        added_tracks = await self.config.added_tracks()
        self.logger.info(f"Previously added tracks: {len(added_tracks)}")

        tracks_to_add = []
        for track_id in track_ids:
            self.logger.info(f"Processing track ID: {track_id}")
            if track_id in current_track_ids:
                self.logger.info(f"Track {track_id} already in playlist. Skipping.")
                continue
            if track_id in added_tracks:
                self.logger.info(f"Track {track_id} already added previously. Skipping.")
                continue

            # Get track details
            self.logger.info(f"Fetching details for track {track_id}")
            async with aiohttp.ClientSession() as session:
                async with session.get(f"https://api.spotify.com/v1/tracks/{track_id}", headers=headers) as resp:
                    if resp.status != 200:
                        self.logger.error(f"Failed to get track details for {track_id}. Status: {resp.status}")
                        continue
                    track_data = await resp.json()
            
            track_name = track_data['name']
            artist_name = track_data['artists'][0]['name']
            
            self.logger.info(f"Checking track: '{track_name}' by {artist_name}")
            
            # Get lyrics and check for offensive words
            self.logger.info(f"Fetching lyrics for '{track_name}' by {artist_name}")
            lyrics = await self.get_lyrics(track_name, artist_name)
            if lyrics is None:
                self.logger.info(f"Couldn't find lyrics for '{track_name}' by {artist_name}. Adding to playlist.")
                tracks_to_add.append(track_id)
            elif not self.contains_offensive_words(lyrics):
                self.logger.info(f"No offensive words found in '{track_name}' by {artist_name}. Adding to playlist.")
                tracks_to_add.append(track_id)
            else:
                self.logger.info(f"Skipped track '{track_name}' by {artist_name} due to offensive lyrics")

        self.logger.info(f"Tracks to add after filtering: {len(tracks_to_add)}")

        # Add new tracks in chunks
        chunk_size = 100
        for i in range(0, len(tracks_to_add), chunk_size):
            chunk = tracks_to_add[i:i + chunk_size]
            data = {"uris": [f"spotify:track:{track_id}" for track_id in chunk]}
            
            async with aiohttp.ClientSession() as session:
                async with session.post(f"https://api.spotify.com/v1/playlists/{playlist_id}/tracks", headers=headers, json=data) as resp:
                    if resp.status == 401:
                        self.logger.warning("Spotify token expired, attempting to refresh")
                        success = await self.refresh_spotify_token()
                        if success:
                            headers["Authorization"] = f"Bearer {self.spotify_token}"
                            async with session.post(f"https://api.spotify.com/v1/playlists/{playlist_id}/tracks", headers=headers, json=data) as retry_resp:
                                if retry_resp.status != 201:
                                    error_text = await retry_resp.text()
                                    self.logger.error(f"Failed to add tracks to playlist after token refresh. Status: {retry_resp.status}, Response: {error_text}")
                                    return False
                        else:
                            self.logger.error("Failed to refresh Spotify token")
                            return False
                    elif resp.status != 201:
                        error_text = await resp.text()
                        self.logger.error(f"Failed to add tracks to playlist. Status: {resp.status}, Response: {error_text}")
                        return False
                    else:
                        self.logger.info(f"Successfully added {len(chunk)} tracks to playlist")
                        added_tracks.extend(chunk)

        # Update the list of added tracks in the config
        await self.config.added_tracks.set(added_tracks)
        self.logger.info(f"Updated added_tracks in config. Total: {len(added_tracks)}")
        return True

    @url_check.before_loop
    async def before_url_check(self):
        await self.bot.wait_until_ready()

    @commands.command()
    @commands.admin()
    async def refresh_spotify_token(self, ctx):
        """Manually refresh the Spotify access token."""
        old_token = self.spotify_token
        new_token = await self.refresh_spotify_token()
        if new_token:
            self.spotify_token = new_token
            await ctx.send("Spotify token refreshed successfully.")
            self.logger.info("Spotify token refreshed manually")
        else:
            await ctx.send("Failed to refresh Spotify token. Check your client credentials.")
            self.logger.error("Failed to refresh Spotify token manually")

    @commands.command()
    @commands.admin()
    async def reset_last_message(self, ctx):
        """Reset the last processed message ID to start checking from the beginning."""
        await self.config.last_message_id.set(None)
        self.logger.info("Last message ID reset to None")
        await ctx.send("Last processed message ID has been reset. The next URL grab will start from the beginning of the channel history.")

    @commands.command()
    @commands.admin()
    async def check_spotify_token(self, ctx):
        """Check the current Spotify token and its scopes."""
        if not self.spotify_token:
            success = await self.refresh_spotify_token()
            if not success:
                await ctx.send("Failed to refresh Spotify token. Please re-authenticate using [p]spotify_auth")
                return

        headers = {
            "Authorization": f"Bearer {self.spotify_token}",
            "Content-Type": "application/json"
        }

        async with aiohttp.ClientSession() as session:
            async with session.get("https://api.spotify.com/v1/me", headers=headers) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    await ctx.send(f"Spotify token is valid. User: {data['display_name']}")
                else:
                    error_text = await resp.text()
                    await ctx.send(f"Failed to check Spotify token. Status: {resp.status}, Response: {error_text}")

    @commands.command()
    @commands.admin()
    async def check_spotify_config(self, ctx):
        """Check the current Spotify configuration."""
        client_id = await self.config.spotify_client_id()
        client_secret = await self.config.spotify_client_secret()
        playlist_id = await self.config.spotify_playlist_id()

        await ctx.send(f"Spotify Client ID: {'Set' if client_id else 'Not set'}\n"
                       f"Spotify Client Secret: {'Set' if client_secret else 'Not set'}\n"
                       f"Spotify Playlist ID: {playlist_id if playlist_id else 'Not set'}")

    async def auto_refresh_token(self):
        while True:
            if self.spotify_token_expiry and self.spotify_token_expiry - datetime.now() < timedelta(minutes=5):
                await self.refresh_spotify_token()
            await asyncio.sleep(60)  # Check every minute

    async def ensure_spotify_token(self):
        if not self.spotify_token or (self.spotify_token_expiry and datetime.now() > self.spotify_token_expiry):
            success = await self.refresh_spotify_token()
            if not success:
                self.logger.error("Failed to refresh Spotify token")
                return False
        return True

async def setup(bot):
    await bot.add_cog(URLGrabber(bot))