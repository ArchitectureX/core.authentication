#!/bin/bash

# Get the last commit message
lastCommit=$(git log -1 --pretty=oneline)

# Get the commit message type
types=("fix" "feat" "major")

# Extract package name from package.json using grep and awk
packageName=$(grep '"name"' ./package.json | awk -F': ' '{print $2}' | tr -d '",')

# Check if package name has '@organization/package' format
if [[ $packageName == @*/* ]]; then
  # Extract organization and package
  organization="${packageName#*@}"
  organization="${organization%/*}"
  package="${packageName#*/}"
else
  # If not, consider entire packageName as the package name and organization will be empty
  organization=""
  package="$packageName"
fi

# Check if the package name was found
if [ -z "$packageName" ]; then
  echo "Could not extract package name."
  exit 1
fi

# Show the package name, organization and package
echo "Package: $package"
echo "Last Commit: $lastCommit"

# Function to version the package
versionPackage() {
  versionType=$1

  # Check if the version type is valid
  case $versionType in
    "fix") versionCommand="patch" ;;
    "feat") versionCommand="minor" ;;
    "major") versionCommand="major" ;;
    *) echo "Invalid version type"; exit 1 ;;
  esac

  # Versioning the package
  echo "Versioning @$organization/$package ($versionType)"

  # Check if the working directory is clean
  if [ -z "$(git status --porcelain)" ]; then
    echo "Working directory is clean. Proceeding with versioning."
    npm run lint
    npm version $versionCommand
  else
    echo "Working directory has uncommitted changes. Committing them now."

    # Configuring git (useful in CI environments where it might not be set)
    git config user.name "Auto Commit Bot"
    git config user.email "foggdev@gmail.com"

    # Add all changes to the staging area
    git add .

    # Commit the changes
    git commit -m "chore: Auto commit before version bump"

    # Proceed with versioning
    npm run lint
    npm version $versionCommand
  fi

  # Pushing the versioned package
  echo "Creating a $versionCommand version: $execute"
  push=$(git push origin main -f)

  # Publishing the package
  echo "$push"
  publish=$(npm publish)

  # Show the publish output
  echo "$publish"
}

# Check if the last commit message contains any of the types
for type in "${types[@]}"; do
  if [[ "$lastCommit" == *"$type"* ]]; then
    versionPackage $type
    exit
  fi
done

echo "No version type found in the last commit message. Skipping versioning."
exit
