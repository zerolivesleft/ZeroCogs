import re
import aiohttp
from redbot.core import commands, Config
from discord.ext import tasks
from collections import defaultdict
from base64 import b64encode
import logging
import discord

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
            "added_tracks": [],
            "last_message_id": None,
        }
        self.config.register_global(**default_global)
        self.url_pattern = re.compile(r'https://open\.spotify\.com/track/([a-zA-Z0-9]+)')
        self.url_check.start()
        self.spotify_token = None
        self.logger = logging.getLogger("red.PlaylistCreator")
        self.logger.info("PlaylistCreator cog initialized")

    def cog_unload(self):
        self.url_check.cancel()

    @commands.group()
    @commands.admin_or_permissions(manage_guild=True)
    async def playlistset(self, ctx):
        """Configure the PlaylistCreator settings."""
        self.logger.info("playlistset command invoked")
        if ctx.invoked_subcommand is None:
            await ctx.send_help(ctx.command)

    @playlistset.command(name="channel")
    async def set_channel(self, ctx, channel_id: int):
        """Set the channel to monitor for Spotify links."""
        await self.config.channel_id.set(channel_id)
        await ctx.send(f"Channel set to {channel_id}")

    @playlistset.command(name="user")
    async def set_user(self, ctx, user_id: int):
        """Set the user ID for Spotify authentication."""
        await self.config.user_id.set(user_id)
        await ctx.send(f"User ID set to {user_id}")

    @playlistset.command(name="spotify_client_id")
    async def set_spotify_client_id(self, ctx, client_id: str):
        """Set the Spotify Client ID."""
        await self.config.spotify_client_id.set(client_id)
        await ctx.send("Spotify Client ID set.")

    @playlistset.command(name="spotify_client_secret")
    async def set_spotify_client_secret(self, ctx, client_secret: str):
        """Set the Spotify Client Secret."""
        await self.config.spotify_client_secret.set(client_secret)
        await ctx.send("Spotify Client Secret set.")

    @playlistset.command(name="spotify_playlist_id")
    async def set_spotify_playlist_id(self, ctx, playlist_id: str):
        """Set the Spotify Playlist ID."""
        await self.config.spotify_playlist_id.set(playlist_id)
        await ctx.send(f"Spotify Playlist ID set to {playlist_id}")

    @commands.command()
    @commands.admin_or_permissions(manage_guild=True)
    async def playlistsettings(self, ctx):
        """Show the current PlaylistCreator settings."""
        channel_id = await self.config.channel_id()
        user_id = await self.config.user_id()
        spotify_client_id = await self.config.spotify_client_id()
        spotify_playlist_id = await self.config.spotify_playlist_id()

        settings = (
            f"Channel ID: {channel_id}\n"
            f"User ID: {user_id}\n"
            f"Spotify Client ID: {'Set' if spotify_client_id else 'Not set'}\n"
            f"Spotify Client Secret: {'Set' if await self.config.spotify_client_secret() else 'Not set'}\n"
            f"Spotify Playlist ID: {spotify_playlist_id}"
        )
        await ctx.send(f"Current settings:\n```\n{settings}\n```")

    @commands.command()
    async def seturldm(self, ctx, user_id: int):
        """Set the user to send grabbed URLs to."""
        await self.config.user_id.set(user_id)
        await ctx.send(f"URL recipient set to user with ID {user_id}")

    @commands.command()
    async def setspotifycredentials(self, ctx, client_id: str, client_secret: str):
        """Set Spotify API credentials."""
        await self.config.spotify_client_id.set(client_id)
        await self.config.spotify_client_secret.set(client_secret)
        await ctx.send("Spotify credentials set.")

    @commands.command()
    async def setspotifyplaylist(self, ctx, playlist_id: str):
        """Set Spotify playlist ID."""
        await self.config.spotify_playlist_id.set(playlist_id)
        await ctx.send(f"Spotify playlist ID set to {playlist_id}")

    @commands.command()
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

    async def get_spotify_token(self):
        client_id = await self.config.spotify_client_id()
        client_secret = await self.config.spotify_client_secret()
        if not client_id or not client_secret:
            self.logger.error("Spotify client ID or client secret not set")
            return None

        auth = b64encode(f"{client_id}:{client_secret}".encode()).decode()
        headers = {
            "Authorization": f"Basic {auth}",
            "Content-Type": "application/x-www-form-urlencoded"
        }
        data = {"grant_type": "client_credentials"}

        async with aiohttp.ClientSession() as session:
            async with session.post("https://accounts.spotify.com/api/token", headers=headers, data=data) as resp:
                if resp.status == 200:
                    json_data = await resp.json()
                    self.logger.info("Successfully obtained Spotify token")
                    return json_data["access_token"]
                else:
                    error_text = await resp.text()
                    self.logger.error(f"Failed to get Spotify token. Status: {resp.status}, Response: {error_text}")
        return None

    @playlistset.command(name="clear_added_tracks")
    async def clear_added_tracks(self, ctx):
        """Clear the list of tracks that have been added to the playlist."""
        await self.config.added_tracks.set([])
        await ctx.send("The list of added tracks has been cleared.")

    async def add_tracks_to_playlist(self, track_ids):
        self.logger.info(f"Attempting to add {len(track_ids)} tracks to playlist")
        if not self.spotify_token:
            self.spotify_token = await self.get_spotify_token()
        if not self.spotify_token:
            self.logger.error("Failed to get Spotify token")
            return

        playlist_id = await self.config.spotify_playlist_id()
        if not playlist_id:
            self.logger.error("Spotify playlist ID not set")
            return

        headers = {
            "Authorization": f"Bearer {self.spotify_token}",
            "Content-Type": "application/json"
        }

        # Get current tracks in the playlist
        async with aiohttp.ClientSession() as session:
            async with session.get(f"https://api.spotify.com/v1/playlists/{playlist_id}/tracks", headers=headers) as resp:
                if resp.status == 200:
                    playlist_tracks = await resp.json()
                    current_track_ids = [item['track']['id'] for item in playlist_tracks['items']]
                    self.logger.info(f"Playlist currently has {len(current_track_ids)} tracks")
                else:
                    self.logger.error(f"Failed to get current playlist tracks. Status: {resp.status}")
                    return

        # Get previously added tracks
        added_tracks = await self.config.added_tracks()
        self.logger.info(f"Previously added tracks: {len(added_tracks)}")

        # Determine which tracks to add
        tracks_to_add = [track_id for track_id in track_ids if track_id not in current_track_ids and track_id not in added_tracks]
        self.logger.info(f"Tracks to add: {len(tracks_to_add)}")

        # Add new tracks
        if tracks_to_add:
            data = {"uris": [f"spotify:track:{track_id}" for track_id in tracks_to_add]}
            async with aiohttp.ClientSession() as session:
                async with session.post(f"https://api.spotify.com/v1/playlists/{playlist_id}/tracks", headers=headers, json=data) as resp:
                    if resp.status == 401:
                        self.logger.warning("Spotify token expired, attempting to refresh")
                        new_token = await self.get_spotify_token()
                        if new_token:
                            self.spotify_token = new_token
                            headers["Authorization"] = f"Bearer {self.spotify_token}"
                            async with session.post(f"https://api.spotify.com/v1/playlists/{playlist_id}/tracks", headers=headers, json=data) as retry_resp:
                                if retry_resp.status != 201:
                                    self.logger.error(f"Failed to add tracks to playlist after token refresh. Status: {retry_resp.status}")
                                else:
                                    self.logger.info(f"Successfully added {len(tracks_to_add)} tracks to playlist after token refresh")
                                    added_tracks.extend(tracks_to_add)
                        else:
                            self.logger.error("Failed to refresh Spotify token")
                    elif resp.status != 201:
                        self.logger.error(f"Failed to add tracks to playlist. Status: {resp.status}")
                    else:
                        self.logger.info(f"Successfully added {len(tracks_to_add)} tracks to playlist")
                        added_tracks.extend(tracks_to_add)

        # Update the list of added tracks in the config
        await self.config.added_tracks.set(added_tracks)
        self.logger.info(f"Updated added_tracks in config. Total: {len(added_tracks)}")

    @url_check.before_loop
    async def before_url_check(self):
        await self.bot.wait_until_ready()

    @commands.command()
    async def refresh_spotify_token(self, ctx):
        """Manually refresh the Spotify access token."""
        old_token = self.spotify_token
        new_token = await self.get_spotify_token()
        if new_token:
            self.spotify_token = new_token
            await ctx.send("Spotify token refreshed successfully.")
            self.logger.info("Spotify token refreshed manually")
        else:
            await ctx.send("Failed to refresh Spotify token. Check your client credentials.")
            self.logger.error("Failed to refresh Spotify token manually")

    @commands.command()
    @commands.admin_or_permissions(manage_guild=True)
    async def reset_last_message(self, ctx):
        """Reset the last processed message ID to start checking from the beginning."""
        await self.config.last_message_id.set(None)
        self.logger.info("Last message ID reset to None")
        await ctx.send("Last processed message ID has been reset. The next URL grab will start from the beginning of the channel history.")

async def setup(bot):
    await bot.add_cog(URLGrabber(bot))