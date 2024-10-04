# Zero's RedBot Cogs Repository

This repository contains custom cogs for Red-DiscordBot.

## Available Cogs

### TwitchScheduleSync

Synchronizes Twitch stream schedules with Discord events. This cog automatically fetches the Twitch schedule for a specified user and creates or updates corresponding Discord events.

### PlaylistCreator (URLGrabber)

Automatically adds Spotify tracks shared in a specific Discord channel to a designated Spotify playlist.

## Installation

To add these cogs to your Red instance:

1. Add this repository:
   ```
   [p]repo add zeros-cogs https://github.com/yourusername/zeros-redbotcogs
   ```

2. Install the desired cog:
   ```
   [p]cog install zeros-cogs TwitchScheduleSync
   [p]cog install zeros-cogs PlaylistCreator
   ```

3. Load the installed cog:
   ```
   [p]load TwitchScheduleSync
   [p]load PlaylistCreator
   ```

## TwitchScheduleSync Setup

1. Obtain Twitch API credentials:
   - Go to https://dev.twitch.tv/console/apps
   - Create a new application or use an existing one
   - Note down the Client ID and generate a new Client Secret

2. Set up the cog:
   ```
   [p]twitchset clientid <your_client_id>
   [p]twitchset clientsecret <your_client_secret>
   [p]twitchset username <twitch_username>
   ```

3. Verify settings:
   ```
   [p]show_twitch_settings
   ```

4. Force a sync:
   ```
   [p]force_sync
   ```

## PlaylistCreator (URLGrabber) Setup

1. Obtain Spotify API credentials:
   - Go to https://developer.spotify.com/dashboard/
   - Create a new application or use an existing one
   - Note down the Client ID and Client Secret

2. Create a Spotify playlist and note down its ID (the last part of the playlist URL)

3. Set up the cog:
   ```
   [p]playlistset channel <channel_id>
   [p]playlistset user <user_id>
   [p]playlistset spotify_client_id <your_spotify_client_id>
   [p]playlistset spotify_client_secret <your_spotify_client_secret>
   [p]playlistset spotify_playlist_id <your_playlist_id>
   ```

4. Verify settings:
   ```
   [p]playlistsettings
   ```

5. The cog will now automatically check for Spotify track URLs in the specified channel every 5 minutes and add them to the designated playlist.

Note: Ensure that the bot has the necessary permissions to read messages in the specified channel.

## Support

If you encounter any issues or have questions, please open an issue in this repository.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the [MIT License](LICENSE).